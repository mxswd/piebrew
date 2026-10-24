/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Piebrew authors
 *
 * A .deb made in memory: an ar archive of debian-binary, control.tar.gz
 * (control, md5sums) and data.tar.gz (the package's entries, each
 * directory above them too, owned by root:wheel), as dpkg-deb makes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <archive.h>
#include <archive_entry.h>

#include "piebrew.h"

static la_ssize_t
to_buf(struct archive *a, void *b, const void *p, size_t n)
{
	(void)a;
	buf_add(b, p, n);
	return (la_ssize_t)n;
}

static struct archive *
tgz_new(struct buf *out)
{
	struct archive *a = archive_write_new();

	archive_write_set_format_gnutar(a);
	archive_write_add_filter_gzip(a);
	archive_write_set_bytes_per_block(a, 0);
	archive_write_open(a, out, NULL, to_buf, NULL);
	return a;
}

static void
tgz_add(struct archive *a, const char *name, enum ent_type type, unsigned mode,
    const void *data, size_t n, const char *target, time_t mtime)
{
	struct archive_entry *e = archive_entry_new();

	archive_entry_set_pathname(e, name);
	archive_entry_set_uid(e, 0);
	archive_entry_set_gid(e, 0);
	archive_entry_set_uname(e, "root");
	archive_entry_set_gname(e, "wheel");
	archive_entry_set_mtime(e, mtime, 0);
	switch (type) {
	case ENT_DIR:
		archive_entry_set_filetype(e, AE_IFDIR);
		archive_entry_set_perm(e, mode);
		break;
	case ENT_LINK:
		archive_entry_set_filetype(e, AE_IFLNK);
		archive_entry_set_perm(e, 0777);
		archive_entry_set_symlink(e, target);
		break;
	case ENT_FILE:
		archive_entry_set_filetype(e, AE_IFREG);
		archive_entry_set_perm(e, mode);
		archive_entry_set_size(e, (la_int64_t)n);
		break;
	}
	archive_write_header(a, e);
	if (type == ENT_FILE && n)
		archive_write_data(a, data, n);
	archive_entry_free(e);
}

struct item {
	const char *path;
	const struct ent *e;	/* NULL: a directory above the entries */
};

static int
item_cmp(const void *a, const void *b)
{
	return strcmp(((const struct item *)a)->path, ((const struct item *)b)->path);
}

static void
ar_member(struct buf *ar, const char *name, const struct buf *data, time_t mtime)
{
	char h[61];

	snprintf(h, sizeof(h), "%-16s%-12lld%-6d%-6d%-8s%-10zu`\n", name, (long long)mtime, 0, 0,
	    "100644", data->n);
	buf_add(ar, h, 60);
	buf_add(ar, data->p, data->n);
	if (data->n & 1)
		buf_add(ar, "\n", 1);
}

int
deb_build(const struct pkg *p, const char *control, struct buf *deb)
{
	struct item *it = xmalloc((p->n * 8 + 8) * sizeof(*it));
	size_t n = 0, m = 0;
	uint64_t bytes = 0;
	time_t now = time(NULL);
	struct buf data = { 0 }, ctl = { 0 }, md5s = { 0 }, ctrl = { 0 }, vers = { 0 };
	struct archive *a;
	char **dirs = NULL;
	size_t ndirs = 0;

	/* The entries, and every directory above them. */
	for (size_t i = 0; i < p->n; i++) {
		it[n++] = (struct item){ p->e[i].path, &p->e[i] };
		if (p->e[i].type == ENT_FILE)
			bytes += p->e[i].data.n;
		for (char *s = p->e[i].path + 1; (s = strchr(s, '/')) != NULL; s++) {
			char *d = strndup(p->e[i].path, (size_t)(s - p->e[i].path));

			dirs = realloc(dirs, (ndirs + 1) * sizeof(char *));
			dirs[ndirs++] = d;
		}
	}
	it = realloc(it, (n + ndirs + 1) * sizeof(*it));
	for (size_t i = 0; i < ndirs; i++)
		it[n++] = (struct item){ dirs[i], NULL };
	qsort(it, n, sizeof(*it), item_cmp);
	/* One item per path: an entry of the package over a directory above. */
	for (size_t i = 0; i < n; i++) {
		if (m > 0 && strcmp(it[m - 1].path, it[i].path) == 0) {
			if (it[i].e != NULL)
				it[m - 1] = it[i];
			continue;
		}
		it[m++] = it[i];
	}

	a = tgz_new(&data);
	tgz_add(a, "./", ENT_DIR, 0755, NULL, 0, NULL, now);
	for (size_t i = 0; i < m; i++) {
		char *name = xasprintf(".%s%s", it[i].path,
		    it[i].e == NULL || it[i].e->type == ENT_DIR ? "/" : "");
		const struct ent *e = it[i].e;

		if (e == NULL)
			tgz_add(a, name, ENT_DIR, 0755, NULL, 0, NULL, now);
		else {
			tgz_add(a, name, e->type, e->mode ? e->mode : 0644, e->data.p, e->data.n, e->target, now);
			if (e->type == ENT_FILE) {
				char h[33];

				md5_hex(e->data.p, e->data.n, h);
				buf_printf(&md5s, "%s  %s\n", h, it[i].path + 1);
			}
		}
		free(name);
	}
	archive_write_close(a);
	archive_write_free(a);

	buf_addstr(&ctrl, control);
	buf_printf(&ctrl, "Installed-Size: %llu\n", (unsigned long long)((bytes + 1023) / 1024 + m / 4));
	a = tgz_new(&ctl);
	tgz_add(a, "./", ENT_DIR, 0755, NULL, 0, NULL, now);
	tgz_add(a, "./control", ENT_FILE, 0644, ctrl.p, ctrl.n, NULL, now);
	tgz_add(a, "./md5sums", ENT_FILE, 0644, md5s.p, md5s.n, NULL, now);
	archive_write_close(a);
	archive_write_free(a);

	buf_addstr(deb, "!<arch>\n");
	buf_addstr(&vers, "2.0\n");
	ar_member(deb, "debian-binary", &vers, now);
	ar_member(deb, "control.tar.gz", &ctl, now);
	ar_member(deb, "data.tar.gz", &data, now);

	for (size_t i = 0; i < ndirs; i++)
		free(dirs[i]);
	free(dirs);
	free(it);
	buf_free(&data);
	buf_free(&ctl);
	buf_free(&md5s);
	buf_free(&ctrl);
	buf_free(&vers);
	return 0;
}
