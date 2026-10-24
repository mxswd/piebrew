/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Piebrew authors
 *
 * piebrew: Homebrew bottles installed as dpkg packages.
 */

#ifndef PIEBREW_H
#define PIEBREW_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define PREFIX		"/opt/homebrew"
#define CELLAR		PREFIX "/Cellar"
#define DEFAULT_API	"https://formulae.brew.sh/api"
#define GHCR		"https://ghcr.io/v2/"
#define DEFAULT_CACHE	"/var/cache/piebrew"

/* A growing byte buffer. */
struct buf {
	uint8_t *p;
	size_t n, cap;
};
void buf_add(struct buf *b, const void *p, size_t n);
void buf_addstr(struct buf *b, const char *s);
void buf_printf(struct buf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void buf_free(struct buf *b);

/* A formula, as the API describes it, with the bottle chosen for us. */
struct formula {
	char *name, *version, *desc, *homepage, *caveats;
	int revision, rebuild, version_scheme;
	bool keg_only, post_install;
	char **deps;			/* runtime dependencies, NULL-terminated */
	char *tag, *url, *sha256, *cellar;
};
int formula_get(const char *name, const char *tag, struct formula *f);
void formula_free(struct formula *f);
char *formula_debversion(const struct formula *f);
char *formula_package(const char *name);

/* One file of the package being made: PATH is absolute (/opt/homebrew/...). */
enum ent_type { ENT_FILE, ENT_DIR, ENT_LINK };
struct ent {
	char *path;
	enum ent_type type;
	unsigned mode;
	struct buf data;		/* ENT_FILE */
	char *target;			/* ENT_LINK */
};
struct pkg {
	struct ent *e;
	size_t n, cap;
	char **syslibs;			/* /usr/lib and /System libraries loaded */
	size_t nsyslibs;
};
struct ent *pkg_add(struct pkg *p, const char *path, enum ent_type type, unsigned mode);
void pkg_free(struct pkg *p);

/* bottle.c: the bottle's tar.gz, in memory, into P (under the Cellar). */
int bottle_read(const struct buf *tgz, const struct formula *f, struct pkg *p, char **kegdir);
/* links.c: opt/<name>, and unless keg-only, brew link's symlinks. */
void links_add(struct pkg *p, const struct formula *f, const char *kegdir);
/* relocate.c */
int relocate_text(struct buf *b, const char *path);
bool is_macho(const struct buf *b);
int macho_fix(struct buf *b, const char *path, struct pkg *p);
/* codesign.c: ad-hoc signature with 4 KB pages; B is a thin 64-bit Mach-O. */
int codesign_adhoc(struct buf *b, const char *path);
/* deb.c */
int deb_build(const struct pkg *p, const char *control, struct buf *deb);
/* fetch.c */
int fetch(const char *url, const char *bearer, bool progress, struct buf *out);
/* util */
void sha256_hex(const void *p, size_t n, char out[65]);
void md5_hex(const void *p, size_t n, char out[33]);
int run(char *const argv[], struct buf *out);
void warnx_(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
extern int verbose;
char *xstrdup(const char *s);
void *xmalloc(size_t n);
char *xasprintf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

#endif
