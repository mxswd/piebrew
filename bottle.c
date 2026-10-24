/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Piebrew authors
 *
 * A bottle (a tar.gz of <name>/<version>/..., the keg) read from memory
 * into a package's entries under /opt/homebrew/Cellar, each file
 * relocated as it comes: nothing is unpacked to disk.
 */

#include <stdlib.h>
#include <string.h>
#include <archive.h>
#include <archive_entry.h>

#include "piebrew.h"

struct ent *
pkg_add(struct pkg *p, const char *path, enum ent_type type, unsigned mode)
{
	struct ent *e;

	if (p->n == p->cap) {
		p->cap = p->cap ? 2 * p->cap : 256;
		p->e = realloc(p->e, p->cap * sizeof(*p->e));
	}
	e = &p->e[p->n++];
	memset(e, 0, sizeof(*e));
	e->path = xstrdup(path);
	e->type = type;
	e->mode = mode;
	return e;
}

void
pkg_free(struct pkg *p)
{
	for (size_t i = 0; i < p->n; i++) {
		free(p->e[i].path);
		free(p->e[i].target);
		buf_free(&p->e[i].data);
	}
	for (size_t i = 0; i < p->nsyslibs; i++)
		free(p->syslibs[i]);
	free(p->syslibs);
	free(p->e);
	memset(p, 0, sizeof(*p));
}

static struct ent *
find(struct pkg *p, const char *path)
{
	for (size_t i = 0; i < p->n; i++)
		if (strcmp(p->e[i].path, path) == 0)
			return &p->e[i];
	return NULL;
}

/* "./a/b/" as "a/b". */
static char *
clean(const char *s)
{
	char *c;
	size_t n;

	while (s[0] == '.' && s[1] == '/')
		s += 2;
	c = xstrdup(s);
	n = strlen(c);
	while (n > 0 && c[n - 1] == '/')
		c[--n] = 0;
	return c;
}

int
bottle_read(const struct buf *tgz, const struct formula *f, struct pkg *p, char **kegdir)
{
	struct archive *a = archive_read_new();
	struct archive_entry *ae;
	int r, ret = 0;

	*kegdir = NULL;
	archive_read_support_filter_all(a);
	archive_read_support_format_tar(a);
	if (archive_read_open_memory(a, tgz->p, tgz->n) != ARCHIVE_OK) {
		warnx_("%s: the bottle: %s", f->name, archive_error_string(a));
		archive_read_free(a);
		return -1;
	}
	while ((r = archive_read_next_header(a, &ae)) == ARCHIVE_OK) {
		char *rel = clean(archive_entry_pathname(ae)), *path, *slash;
		unsigned mode = archive_entry_perm(ae);
		const char *hl = archive_entry_hardlink(ae);
		struct ent *e;

		/* <name>/<keg directory>/... */
		slash = strchr(rel, '/');
		if (rel[0] == 0 || slash == NULL || (size_t)(slash - rel) != strlen(f->name) ||
		    strncmp(rel, f->name, strlen(f->name)) != 0 || strstr(rel, "..") != NULL) {
			if (strcmp(rel, f->name) != 0)
				warnx_("%s: %s is not in the keg, left out", f->name, rel);
			free(rel);
			continue;
		}
		if (*kegdir == NULL) {
			char *end = strchr(slash + 1, '/');

			*kegdir = end ? strndup(slash + 1, (size_t)(end - slash - 1)) : xstrdup(slash + 1);
		}
		path = xasprintf("%s/%s", CELLAR, rel);
		if (hl != NULL) {
			char *t = clean(hl), *tp = xasprintf("%s/%s", CELLAR, t);
			struct ent *src = find(p, tp);

			if (src == NULL || src->type != ENT_FILE)
				warnx_("%s: hard link %s to %s, which is not a file before it", f->name, rel, t);
			else {
				struct buf copy = { 0 };

				buf_add(&copy, src->data.p, src->data.n);
				e = pkg_add(p, path, ENT_FILE, src->mode);
				e->data = copy;
			}
			free(t);
			free(tp);
		} else switch (archive_entry_filetype(ae)) {
		case AE_IFDIR:
			pkg_add(p, path, ENT_DIR, mode);
			break;
		case AE_IFLNK: {
			struct buf t = { 0 };

			e = pkg_add(p, path, ENT_LINK, 0777);
			buf_addstr(&t, archive_entry_symlink(ae));
			relocate_text(&t, path);
			e->target = (char *)t.p;
			break;
		}
		case AE_IFREG: {
			struct buf d = { 0 };
			char tmp[65536];
			la_ssize_t n;

			while ((n = archive_read_data(a, tmp, sizeof(tmp))) > 0)
				buf_add(&d, tmp, (size_t)n);
			if (n < 0) {
				warnx_("%s: %s: %s", f->name, rel, archive_error_string(a));
				ret = -1;
			}
			buf_add(&d, "", 0);
			if (is_macho(&d)) {
				if (macho_fix(&d, path, p) < 0)
					ret = -1;
			} else
				relocate_text(&d, path);
			e = pkg_add(p, path, ENT_FILE, mode);
			e->data = d;
			break;
		}
		default:
			warnx_("%s: %s is not a file, directory or link, left out", f->name, rel);
		}
		free(path);
		free(rel);
	}
	if (r != ARCHIVE_EOF) {
		warnx_("%s: the bottle: %s", f->name, archive_error_string(a));
		ret = -1;
	}
	archive_read_free(a);
	if (*kegdir == NULL) {
		warnx_("%s: the bottle has no keg", f->name);
		ret = -1;
	}
	return ret;
}
