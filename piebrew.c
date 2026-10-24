/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Piebrew authors
 *
 * piebrew: Homebrew bottles installed as dpkg packages. A formula's bottle
 * is fetched into memory, relocated and re-signed there, made into a .deb
 * (brew-<formula>, its files under /opt/homebrew as brew would pour and
 * link them) and installed with dpkg, which then lists, removes and
 * upgrades it like any other package.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cjson/cJSON.h"
#include "piebrew.h"

static bool dry, keep, force, reinstall;
static const char *tag;

/*
 * Formulae seen in this run, each installed once: SEEN_PENDING while its
 * install runs, then 0 or -1, what it came to.
 */
#define SEEN_PENDING 1
static struct seen {
	char *name;
	int status;
} *seen;
static size_t nseen;

static void
usage(void)
{
	fprintf(stderr,
	    "usage: piebrew [-v] install [-n] [--reinstall] [--force] [--keep-deb] [--tag TAG] FORMULA...\n"
	    "       piebrew remove FORMULA...       (also: uninstall)\n"
	    "       piebrew list\n"
	    "       piebrew info FORMULA\n"
	    "       piebrew outdated\n"
	    "       piebrew upgrade [-n] [FORMULA...]\n"
	    "       piebrew --version\n");
	exit(2);
}

static char *
chomp(char *s)
{
	size_t n = strlen(s);

	while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == ' '))
		s[--n] = 0;
	return s;
}

/* The installed version of package PKG, or NULL. */
static char *
installed_version(const char *pkg)
{
	char *argv[] = { "dpkg-query", "-W", "-f", "${db:Status-Abbrev}|${Version}", (char *)pkg, NULL };
	struct buf out = { 0 };
	char *v = NULL;

	if (run(argv, &out) == 0 && out.n > 3 && out.p[0] == 'i' && out.p[1] == 'i') {
		char *bar = strchr((char *)out.p, '|');

		if (bar)
			v = xstrdup(chomp(bar + 1));
	}
	buf_free(&out);
	return v;
}

static bool
version_ge(const char *a, const char *b)
{
	char *argv[] = { "dpkg", "--compare-versions", (char *)a, "ge", (char *)b, NULL };

	return run(argv, NULL) == 0;
}

static char *
arch(void)
{
	char *argv[] = { "dpkg", "--print-architecture", NULL };
	struct buf out = { 0 };
	char *a;

	if (run(argv, &out) == 0 && out.n > 0)
		a = xstrdup(chomp((char *)out.p));
	else
		a = xstrdup("darwin-arm64");
	buf_free(&out);
	return a;
}

/* ghcr.io's anonymous pull token for a blob URL's repository. */
static char *
ghcr_token(const char *url)
{
	const char *repo = url + strlen(GHCR), *end = strstr(repo, "/blobs/");
	struct buf b = { 0 };
	char *turl, *token = NULL;
	cJSON *j;

	if (end == NULL)
		return NULL;
	turl = xasprintf("https://ghcr.io/token?scope=repository:%.*s:pull", (int)(end - repo), repo);
	if (fetch(turl, NULL, false, &b) == 0 && (j = cJSON_ParseWithLength((char *)b.p, b.n)) != NULL) {
		const cJSON *t = cJSON_GetObjectItemCaseSensitive(j, "token");

		if (cJSON_IsString(t))
			token = xstrdup(t->valuestring);
		cJSON_Delete(j);
	}
	free(turl);
	buf_free(&b);
	return token;
}

/* The bottle, fetched and checked against the API's SHA-256. */
static int
get_bottle(const struct formula *f, struct buf *tgz)
{
	const char *mirror = getenv("PIEBREW_BOTTLES");
	char *url, *token = NULL, sum[65];
	int r;

	if (mirror && *mirror && strncmp(f->url, GHCR, strlen(GHCR)) == 0)
		url = xasprintf("%s/%s", mirror, f->url + strlen(GHCR));
	else {
		url = xstrdup(f->url);
		if (strncmp(url, GHCR, strlen(GHCR)) == 0 && (token = ghcr_token(url)) == NULL) {
			fprintf(stderr, "piebrew: %s: no token from ghcr.io\n", f->name);
			free(url);
			return -1;
		}
	}
	fprintf(stderr, "piebrew: fetching %s %s (%s)\n", f->name, f->version, f->tag);
	r = fetch(url, token, true, tgz);
	free(url);
	free(token);
	if (r != 0)
		return -1;
	sha256_hex(tgz->p, tgz->n, sum);
	if (strcmp(sum, f->sha256) != 0) {
		fprintf(stderr, "piebrew: %s: the bottle's SHA-256 is %s, not %s as the API says\n",
		    f->name, sum, f->sha256);
		return -1;
	}
	return 0;
}

/* Whether DEP, a Depends list, names PKG. */
static bool
has_dep(const struct buf *dep, const char *pkg)
{
	size_t l = strlen(pkg);

	for (const char *s = dep->n ? (const char *)dep->p : ""; *s; ) {
		if (strncmp(s, pkg, l) == 0 && (s[l] == ',' || s[l] == 0))
			return true;
		if ((s = strstr(s, ", ")) == NULL)
			break;
		s += 2;
	}
	return false;
}

/*
 * The system packages that own the libraries the bottle loads; a library
 * no package owns and the system does not have is an error, unless
 * --force.
 */
static int
sys_depends(const struct pkg *p, const struct formula *f, struct buf *dep)
{
	int ret = 0;

	for (size_t i = 0; i < p->nsyslibs; i++) {
		char *argv[] = { "dpkg-query", "-S", p->syslibs[i], NULL };
		struct buf out = { 0 };
		struct stat st;

		if (run(argv, &out) == 0 && out.n > 0) {
			/* "pkg[, pkg...]: PATH" (not "diversion by ..."): any one of them. */
			char *save = NULL, *colon = NULL;

			for (char *l = strtok_r((char *)out.p, "\n", &save); l; l = strtok_r(NULL, "\n", &save))
				if (strncmp(l, "diversion ", 10) != 0 && (colon = strstr(l, ": /")) != NULL) {
					struct buf alt = { 0 };

					*colon = 0;
					for (char *s = l; *s; s++)
						if (s[0] == ',' && s[1] == ' ') {
							buf_addstr(&alt, " | ");
							s++;
						} else
							buf_add(&alt, s, 1);
					if (!has_dep(dep, (char *)alt.p))
						buf_printf(dep, "%s%s", dep->n ? ", " : "", (char *)alt.p);
					buf_free(&alt);
					break;
				}
		} else if (stat(p->syslibs[i], &st) != 0) {
			fprintf(stderr, "piebrew: %s loads %s, which this system does not have\n", f->name,
			    p->syslibs[i]);
			ret = -1;
		}
		buf_free(&out);
	}
	return force ? 0 : ret;
}

static char *
control(const struct formula *f, const char *deps)
{
	struct buf c = { 0 };
	char *pkg = formula_package(f->name), *ver = formula_debversion(f), *a = arch();

	buf_printf(&c, "Package: %s\nVersion: %s\nArchitecture: %s\n", pkg, ver, a);
	buf_printf(&c, "Maintainer: piebrew <root@localhost>\nSection: brew\nPriority: optional\n");
	if (deps[0])
		buf_printf(&c, "Depends: %s\n", deps);
	if (f->homepage)
		buf_printf(&c, "Homepage: %s\n", f->homepage);
	buf_printf(&c, "Homebrew-Formula: %s\nHomebrew-Bottle: %s %s\n", f->name, f->tag, f->sha256);
	buf_printf(&c, "Description: %s\n Homebrew's %s %s bottle (%s), poured by piebrew.\n",
	    f->desc && f->desc[0] ? f->desc : f->name, f->name, f->version, f->tag);
	free(pkg);
	free(ver);
	free(a);
	return (char *)c.p;
}

/* The .deb of formula F. */
static int
make_deb(const struct formula *f, struct buf *deb)
{
	struct buf tgz = { 0 }, deps = { 0 };
	struct pkg p = { 0 };
	char *kegdir = NULL, *ctl;
	int ret = -1;

	if (get_bottle(f, &tgz) < 0)
		goto out;
	if ((bottle_read(&tgz, f, &p, &kegdir) < 0 && !force) || kegdir == NULL)
		goto out;
	buf_free(&tgz);
	links_add(&p, f, kegdir);
	for (size_t i = 0; f->deps[i]; i++) {
		char *d = formula_package(f->deps[i]);

		buf_printf(&deps, "%s%s", deps.n ? ", " : "", d);
		free(d);
	}
	if (sys_depends(&p, f, &deps) < 0)
		goto out;
	ctl = control(f, deps.n ? (char *)deps.p : "");
	ret = deb_build(&p, ctl, deb);
	free(ctl);
out:
	buf_free(&tgz);
	buf_free(&deps);
	pkg_free(&p);
	free(kegdir);
	return ret;
}

static int
write_file(const char *path, const struct buf *b)
{
	char *tmp = xasprintf("%s.new", path);
	int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	size_t off = 0;

	if (fd < 0) {
		warn("%s", tmp);
		free(tmp);
		return -1;
	}
	while (off < b->n) {
		ssize_t w = write(fd, b->p + off, b->n - off);

		if (w < 0 && errno == EINTR)
			continue;
		if (w <= 0) {
			warn("%s", tmp);
			close(fd);
			unlink(tmp);
			free(tmp);
			return -1;
		}
		off += (size_t)w;
	}
	close(fd);
	if (rename(tmp, path) < 0) {
		warn("%s", path);
		unlink(tmp);
		free(tmp);
		return -1;
	}
	free(tmp);
	return 0;
}

static const char *
cache_dir(void)
{
	const char *c = getenv("PIEBREW_CACHE");

	if (!(c && *c) && dry && geteuid() != 0)	/* a dry run as a user: no /var/cache */
		c = getenv("TMPDIR") && *getenv("TMPDIR") ? getenv("TMPDIR") : "/tmp";
	c = c && *c ? c : DEFAULT_CACHE;
	if (mkdir(c, 0755) < 0 && errno != EEXIST)
		warn("%s", c);
	return c;
}

/* NAME's entry; a new one, pending, if NEW is set and there is none. */
static struct seen *
seen_get(const char *name, bool new)
{
	for (size_t i = 0; i < nseen; i++)
		if (strcmp(seen[i].name, name) == 0)
			return &seen[i];
	if (!new)
		return NULL;
	seen = realloc(seen, (nseen + 1) * sizeof(*seen));
	seen[nseen] = (struct seen){ xstrdup(name), SEEN_PENDING };
	return &seen[nseen++];
}

static void
seen_set(const char *name, int status)
{
	seen_get(name, true)->status = status;
}

/*
 * Formula NAME installed (its dependencies first), or upgraded if the API
 * has a newer bottle; AS_DEP marks a package new to the system as
 * installed automatically, for apt autoremove.
 */
static int
install(const char *name, bool as_dep)
{
	struct formula f;
	struct buf deb = { 0 };
	char *pkg = NULL, *have = NULL, *want = NULL, *path = NULL;
	int ret = -1;

	struct seen *s = seen_get(name, false);

	if (s != NULL)	/* done, or (a dependency cycle) under way */
		return s->status == SEEN_PENDING ? 0 : s->status;
	seen_set(name, SEEN_PENDING);
	if (formula_get(name, tag, &f) < 0) {
		seen_set(name, -1);
		return -1;
	}
	if (strcmp(f.name, name) != 0) {	/* an alias */
		if ((s = seen_get(f.name, false)) != NULL) {
			ret = s->status == SEEN_PENDING ? 0 : s->status;
			seen_set(name, ret);
			formula_free(&f);
			return ret;
		}
		seen_set(f.name, SEEN_PENDING);
	}
	for (size_t i = 0; f.deps[i]; i++)
		if (install(f.deps[i], true) < 0)
			goto out;
	pkg = formula_package(f.name);
	have = installed_version(pkg);
	want = formula_debversion(&f);
	if (have && !reinstall && version_ge(have, want)) {
		if (!as_dep)
			printf("piebrew: %s %s is installed already\n", pkg, have);
		ret = 0;
		goto out;
	}
	if (make_deb(&f, &deb) < 0)
		goto out;
	path = xasprintf("%s/%s_%s_darwin-arm64.deb", cache_dir(), pkg, want);
	if (write_file(path, &deb) < 0)
		goto out;
	if (dry) {
		printf("piebrew: %s (not installed: -n)\n", path);
		ret = 0;
		goto out;
	}
	char *dpkg[] = { "dpkg", "-i", path, NULL };

	if (run(dpkg, NULL) != 0) {
		fprintf(stderr, "piebrew: dpkg -i %s failed\n", path);
		goto out;
	}
	if (as_dep && have == NULL) {
		char *mark[] = { "apt-mark", "auto", pkg, NULL };
		struct buf quiet = { 0 };

		run(mark, &quiet);
		buf_free(&quiet);
	}
	if (!keep)
		unlink(path);
	if (f.caveats && f.caveats[0])
		printf("==> Caveats (%s)\n%s\n", f.name, f.caveats);
	if (f.post_install)
		warnx_("%s has a post-install step (Ruby, in its formula), which piebrew does not run", f.name);
	ret = 0;
out:
	seen_set(name, ret);
	seen_set(f.name, ret);
	buf_free(&deb);
	formula_free(&f);
	free(pkg);
	free(have);
	free(want);
	free(path);
	return ret;
}

/* The installed brew-* packages: "PACKAGE|VERSION|FORMULA" lines. */
static char **
installed(size_t *n)
{
	char *argv[] = { "dpkg-query", "-W", "-f",
	    "${db:Status-Abbrev}|${Package}|${Version}|${Homebrew-Formula}\n", "brew-*", NULL };
	struct buf out = { 0 };
	char **v = NULL, *save = NULL;

	*n = 0;
	run(argv, &out);
	for (char *l = strtok_r((char *)out.p ? (char *)out.p : "", "\n", &save); l;
	    l = strtok_r(NULL, "\n", &save)) {
		if (strncmp(l, "ii", 2) != 0 || strchr(l, '|') == NULL)
			continue;
		v = realloc(v, (*n + 1) * sizeof(char *));
		v[(*n)++] = xstrdup(strchr(l, '|') + 1);
	}
	buf_free(&out);
	return v;
}

/* PACKAGE|VERSION|FORMULA split; FORMULA from the name if it is empty. */
static void
split(char *l, char **pkg, char **ver, char **formula)
{
	*pkg = l;
	*ver = strchr(l, '|');
	*(*ver)++ = 0;
	*formula = strchr(*ver, '|');
	*(*formula)++ = 0;
	if (**formula == 0)
		*formula = *pkg + 5;
}

static int
cmd_list(void)
{
	size_t n;
	char **v = installed(&n), *pkg, *ver, *formula;

	for (size_t i = 0; i < n; i++) {
		split(v[i], &pkg, &ver, &formula);
		printf("%-24s %-20s %s\n", formula, ver, pkg);
		free(v[i]);
	}
	free(v);
	return 0;
}

static int
cmd_outdated(bool upgrade, int argc, char **argv)
{
	size_t n;
	char **v = installed(&n), *pkg, *ver, *formula;
	bool *matched = xmalloc((size_t)argc + 1);
	int ret = 0;

	for (size_t i = 0; i < n; i++) {
		struct formula f;
		char *want;
		bool chosen = argc == 0;

		split(v[i], &pkg, &ver, &formula);
		for (int k = 0; k < argc; k++)
			if (strcmp(argv[k], formula) == 0 || strcmp(argv[k], pkg) == 0)
				chosen = matched[k] = true;
		if (!chosen || formula_get(formula, tag, &f) < 0) {
			ret |= chosen;
			free(v[i]);
			continue;
		}
		want = formula_debversion(&f);
		if (!version_ge(ver, want)) {
			printf("%s %s < %s\n", formula, ver, want);
			if (upgrade && install(formula, false) < 0)
				ret = 1;
		}
		free(want);
		formula_free(&f);
		free(v[i]);
	}
	for (int k = 0; k < argc; k++)
		if (!matched[k]) {
			fprintf(stderr, "piebrew: %s is not installed\n", argv[k]);
			ret = 1;
		}
	free(matched);
	free(v);
	return ret;
}

static int
cmd_info(const char *name)
{
	struct formula f;
	char *pkg, *ver, *have;

	if (formula_get(name, tag, &f) < 0)
		return 1;
	pkg = formula_package(f.name);
	ver = formula_debversion(&f);
	have = installed_version(pkg);
	printf("%s %s%s: %s\n", f.name, f.version, f.keg_only ? " (keg-only)" : "", f.desc ? f.desc : "");
	printf("homepage:   %s\n", f.homepage ? f.homepage : "");
	printf("bottle:     %s %s\n", f.tag, f.url);
	printf("package:    %s %s, %s\n", pkg, ver, have ? have : "not installed");
	printf("depends on:");
	for (size_t i = 0; f.deps[i]; i++)
		printf(" %s", f.deps[i]);
	printf("\n");
	free(pkg);
	free(ver);
	free(have);
	formula_free(&f);
	return 0;
}

static int
cmd_remove(int argc, char **argv)
{
	char **args = xmalloc(((size_t)argc + 3) * sizeof(char *));
	int n = 0, r;

	args[n++] = "dpkg";
	args[n++] = "-r";
	for (int i = 0; i < argc; i++)
		args[n++] = strncmp(argv[i], "brew-", 5) == 0 ? argv[i] : formula_package(argv[i]);
	args[n] = NULL;
	r = run(args, NULL);
	free(args);
	return r == 0 ? 0 : 1;
}

int
main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "dry-run", no_argument, NULL, 'n' },
		{ "keep-deb", no_argument, NULL, 'k' },
		{ "force", no_argument, NULL, 'f' },
		{ "reinstall", no_argument, NULL, 'r' },
		{ "tag", required_argument, NULL, 't' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "version", no_argument, NULL, 'V' },
		{ NULL, 0, NULL, 0 },
	};
	const char *cmd;
	int c;

	/* Options before and after the command. */
	while ((c = getopt_long(argc, argv, "+nkfrt:vV", opts, NULL)) != -1) {
		switch (c) {
		case 'n': dry = true; break;
		case 'k': keep = true; break;
		case 'f': force = true; break;
		case 'r': reinstall = true; break;
		case 't': tag = optarg; break;
		case 'v': verbose = 1; break;
		case 'V': printf("piebrew %s\n", PIEBREW_VERSION); return 0;
		default: usage();
		}
	}
	if (optind >= argc)
		usage();
	cmd = argv[optind];
	argc -= optind + 1;
	argv += optind + 1;
	{
		/* options after the command */
		int n = 0;
		char **rest = xmalloc(((size_t)argc + 1) * sizeof(char *));

		for (int i = 0; i < argc; i++) {
			const char *a = argv[i];

			if (strcmp(a, "-n") == 0 || strcmp(a, "--dry-run") == 0) dry = true;
			else if (strcmp(a, "--keep-deb") == 0) keep = true;
			else if (strcmp(a, "--force") == 0) force = true;
			else if (strcmp(a, "--reinstall") == 0) reinstall = true;
			else if (strcmp(a, "-v") == 0) verbose = 1;
			else if (strcmp(a, "--tag") == 0 && i + 1 < argc) tag = argv[++i];
			else if (a[0] == '-') usage();
			else rest[n++] = argv[i];
		}
		argc = n;
		argv = rest;
	}
	if ((strcmp(cmd, "install") == 0 || strcmp(cmd, "upgrade") == 0 || strcmp(cmd, "remove") == 0 ||
	    strcmp(cmd, "uninstall") == 0) && !dry && geteuid() != 0)
		errx(1, "%s: run it as root (dpkg needs to be)", cmd);
	if (strcmp(cmd, "install") == 0) {
		int ret = 0;

		if (argc == 0)
			usage();
		for (int i = 0; i < argc; i++)
			if (install(argv[i], false) < 0)
				ret = 1;
		return ret;
	}
	if (strcmp(cmd, "remove") == 0 || strcmp(cmd, "uninstall") == 0)
		return argc ? cmd_remove(argc, argv) : (usage(), 2);
	if (strcmp(cmd, "list") == 0)
		return cmd_list();
	if (strcmp(cmd, "info") == 0)
		return argc == 1 ? cmd_info(argv[0]) : (usage(), 2);
	if (strcmp(cmd, "outdated") == 0)
		return cmd_outdated(false, argc, argv);
	if (strcmp(cmd, "upgrade") == 0)
		return cmd_outdated(true, argc, argv);
	usage();
}
