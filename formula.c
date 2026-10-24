/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Piebrew authors
 *
 * A formula from Homebrew's JSON API (formulae.brew.sh, or PIEBREW_API),
 * with the bottle for this system chosen, and its dpkg name and version.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cjson/cJSON.h"
#include "piebrew.h"

/*
 * The bottles a system that is macOS 26 (Tahoe) to its programs can pour,
 * newest first; "all" is a bottle with no Mach-O files in it.
 */
static const char *const tags[] = {
	"arm64_tahoe", "arm64_sequoia", "arm64_sonoma", "arm64_ventura", "arm64_monterey",
	"arm64_big_sur", "all",
};

static char *
str(const cJSON *o, const char *key)
{
	const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);

	return cJSON_IsString(v) ? xstrdup(v->valuestring) : NULL;
}

static int
num(const cJSON *o, const char *key)
{
	const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, key);

	return cJSON_IsNumber(v) ? v->valueint : 0;
}

static bool
flag(const cJSON *o, const char *key)
{
	return cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(o, key));
}

int
formula_get(const char *name, const char *tag, struct formula *f)
{
	const char *api = getenv("PIEBREW_API");
	struct buf b = { 0 };
	char *url;
	cJSON *j, *bottle, *files, *deps, *file = NULL;
	int r;

	memset(f, 0, sizeof(*f));
	url = xasprintf("%s/formula/%s.json", api && *api ? api : DEFAULT_API, name);
	r = fetch(url, NULL, false, &b);
	free(url);
	if (r == 404) {
		fprintf(stderr, "piebrew: no formula %s\n", name);
		buf_free(&b);
		return -1;
	}
	if (r != 0) {
		buf_free(&b);
		return -1;
	}
	j = cJSON_ParseWithLength((const char *)b.p, b.n);
	buf_free(&b);
	if (j == NULL) {
		fprintf(stderr, "piebrew: %s: the API's answer is not JSON\n", name);
		return -1;
	}
	f->name = str(j, "name");
	f->desc = str(j, "desc");
	f->homepage = str(j, "homepage");
	f->caveats = str(j, "caveats");
	f->version = str(cJSON_GetObjectItemCaseSensitive(j, "versions"), "stable");
	f->revision = num(j, "revision");
	f->version_scheme = num(j, "version_scheme");
	f->keg_only = flag(j, "keg_only");
	f->post_install = flag(j, "post_install_defined");
	if (f->name == NULL || f->version == NULL) {
		fprintf(stderr, "piebrew: %s: the API's answer has no name or version\n", name);
		goto fail;
	}
	if (flag(j, "disabled")) {
		fprintf(stderr, "piebrew: %s is disabled in Homebrew\n", f->name);
		goto fail;
	}
	if (flag(j, "deprecated"))
		warnx_("%s is deprecated in Homebrew", f->name);
	deps = cJSON_GetObjectItemCaseSensitive(j, "dependencies");
	f->deps = xmalloc(((size_t)cJSON_GetArraySize(deps) + 1) * sizeof(char *));
	size_t nd = 0;
	for (cJSON *d = deps ? deps->child : NULL; d; d = d->next)
		if (cJSON_IsString(d))
			f->deps[nd++] = xstrdup(d->valuestring);

	bottle = cJSON_GetObjectItemCaseSensitive(cJSON_GetObjectItemCaseSensitive(j, "bottle"), "stable");
	f->rebuild = num(bottle, "rebuild");
	files = cJSON_GetObjectItemCaseSensitive(bottle, "files");
	if (tag) {
		file = cJSON_GetObjectItemCaseSensitive(files, tag);
		f->tag = xstrdup(tag);
	} else
		for (size_t i = 0; i < sizeof(tags) / sizeof(tags[0]) && file == NULL; i++)
			if ((file = cJSON_GetObjectItemCaseSensitive(files, tags[i])) != NULL)
				f->tag = xstrdup(tags[i]);
	if (file == NULL) {
		fprintf(stderr, "piebrew: %s has no bottle for arm64 macOS%s%s\n", f->name,
		    tag ? " tag " : "", tag ? tag : "");
		goto fail;
	}
	f->url = str(file, "url");
	f->sha256 = str(file, "sha256");
	f->cellar = str(file, "cellar");
	if (f->url == NULL || f->sha256 == NULL) {
		fprintf(stderr, "piebrew: %s: the bottle has no url or sha256\n", f->name);
		goto fail;
	}
	if (f->cellar && strcmp(f->cellar, ":any") != 0 && strcmp(f->cellar, ":any_skip_relocation") != 0 &&
	    strcmp(f->cellar, CELLAR) != 0) {
		fprintf(stderr, "piebrew: %s: the bottle works only in %s\n", f->name, f->cellar);
		goto fail;
	}
	cJSON_Delete(j);
	return 0;
fail:
	cJSON_Delete(j);
	formula_free(f);
	return -1;
}

void
formula_free(struct formula *f)
{
	free(f->name);
	free(f->version);
	free(f->desc);
	free(f->homepage);
	free(f->caveats);
	for (size_t i = 0; f->deps && f->deps[i]; i++)
		free(f->deps[i]);
	free(f->deps);
	free(f->tag);
	free(f->url);
	free(f->sha256);
	free(f->cellar);
	memset(f, 0, sizeof(*f));
}

/*
 * The dpkg version: the formula's version_scheme as the epoch, if any (a
 * new scheme's versions may sort lower), the formula's version (characters dpkg does not take
 * as '+', and "0+" before one that does not start with a digit), "+<n>"
 * for a revision, and the bottle's rebuild as the Debian revision.
 */
char *
formula_debversion(const struct formula *f)
{
	struct buf v = { 0 };

	if (f->version_scheme > 0)
		buf_printf(&v, "%d:", f->version_scheme);
	if (!isdigit((unsigned char)f->version[0]))
		buf_addstr(&v, "0+");
	for (const char *s = f->version; *s; s++)
		buf_add(&v, isalnum((unsigned char)*s) || strchr(".+~", *s) ? s : "+", 1);
	if (f->revision)
		buf_printf(&v, "+%d", f->revision);
	buf_printf(&v, "-%d", f->rebuild);
	return (char *)v.p;
}

/* brew-<name>, lower case, with what dpkg does not take in names as '-'. */
char *
formula_package(const char *name)
{
	struct buf p = { 0 };

	buf_addstr(&p, "brew-");
	for (const char *s = name; *s; s++) {
		char c = (char)tolower((unsigned char)*s);

		buf_add(&p, isalnum((unsigned char)c) || c == '+' || c == '.' ? &c : "-", 1);
	}
	return (char *)p.p;
}
