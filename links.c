/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Piebrew authors
 *
 * What `brew link` makes, as entries of the package: opt/<name>, the
 * keg's stable path, and unless the formula is keg-only, a symlink in
 * /opt/homebrew/{bin,sbin,lib,...} for each file and link in the keg's
 * directories of those names. Two packages linking the same path is
 * then a file conflict, which dpkg refuses, as brew link does.
 */

#include <stdlib.h>
#include <string.h>

#include "piebrew.h"

static const char *const linked[] = {
	"bin", "sbin", "lib", "include", "share", "etc", "Frameworks",
};

/* Directories brew never links into. */
static bool
skipped(const char *rel)
{
	return strcmp(rel, "share/info/dir") == 0 || strcmp(rel, "lib/charset.alias") == 0 ||
	    strncmp(rel, "share/locale/locale.alias", 25) == 0;
}

/* The relative target from /opt/homebrew/REL to the keg's KEGREL. */
static char *
reltarget(const char *rel, const char *kegrel)
{
	struct buf t = { 0 };

	for (const char *s = rel; (s = strchr(s, '/')) != NULL; s++)
		buf_addstr(&t, "../");
	buf_addstr(&t, kegrel);
	return (char *)t.p;
}

void
links_add(struct pkg *p, const struct formula *f, const char *kegdir)
{
	char *keg = xasprintf("%s/%s/%s/", CELLAR, f->name, kegdir);
	char *opt = xasprintf("%s/opt/%s", PREFIX, f->name);
	size_t kl = strlen(keg), n = p->n;
	struct ent *e;

	e = pkg_add(p, opt, ENT_LINK, 0777);
	e->target = xasprintf("../Cellar/%s/%s", f->name, kegdir);
	free(opt);
	if (f->keg_only) {
		free(keg);
		return;
	}
	for (size_t i = 0; i < n; i++) {
		const char *rel;
		char *path, *kegrel;
		bool ok = false;

		if (p->e[i].type == ENT_DIR || strncmp(p->e[i].path, keg, kl) != 0)
			continue;
		rel = p->e[i].path + kl;
		for (size_t k = 0; k < sizeof(linked) / sizeof(linked[0]); k++) {
			size_t l = strlen(linked[k]);

			if (strncmp(rel, linked[k], l) == 0 && rel[l] == '/')
				ok = true;
		}
		if (!ok || skipped(rel))
			continue;
		path = xasprintf("%s/%s", PREFIX, rel);
		kegrel = xasprintf("Cellar/%s/%s/%s", f->name, kegdir, rel);
		e = pkg_add(p, path, ENT_LINK, 0777);
		e->target = reltarget(rel, kegrel);
		free(path);
		free(kegrel);
	}
	free(keg);
}
