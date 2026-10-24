/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Piebrew authors
 *
 * Relocation, as brew does when it pours a bottle: the placeholders a
 * bottle carries for the paths it was built for are replaced with ours,
 * in text files and in Mach-O load commands (the libraries' names and
 * run paths). Mach-O files are then re-signed (codesign.c), all of them,
 * so that every signature has 4 KB pages.
 *
 * A system library a file loads that this system does not have, and from
 * which it imports no symbol, is weak-linked: dyld then goes on without
 * it. Programs that use gnulib's intlmacosx.m4 (libunistring, gettext,
 * ...) link CoreServices for its side effect on Apple's CoreFoundation,
 * which ours does not need, and import nothing from it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "piebrew.h"

static const struct {
	const char *from, *to;
} placeholders[] = {
	{ "@@HOMEBREW_PREFIX@@", PREFIX },
	{ "@@HOMEBREW_CELLAR@@", CELLAR },
	{ "@@HOMEBREW_REPOSITORY@@", PREFIX },
	{ "@@HOMEBREW_LIBRARY@@", PREFIX "/Library" },
	{ "@@HOMEBREW_PERL@@", "/usr/bin/perl" },
	{ "@@HOMEBREW_JAVA@@", PREFIX "/opt/openjdk/libexec/openjdk.jdk/Contents/Home" },
};

#define MH_MAGIC_64		0xfeedfacfu
#define FAT_MAGIC		0xcafebabeu
#define FAT_MAGIC_64		0xcafebabfu
#define CPU_TYPE_ARM64		0x0100000c
#define MH_OBJECT		0x1
#define LC_SEGMENT_64		0x19
#define LC_LOAD_DYLIB		0xc
#define LC_ID_DYLIB		0xd
#define LC_LAZY_LOAD_DYLIB	0x20
#define LC_LOAD_WEAK_DYLIB	0x80000018u
#define LC_RPATH		0x8000001cu
#define LC_REEXPORT_DYLIB	0x8000001fu
#define LC_LOAD_UPWARD_DYLIB	0x80000023u
#define LC_DYLD_INFO		0x22
#define LC_DYLD_INFO_ONLY	0x80000022u
#define LC_DYLD_CHAINED_FIXUPS	0x80000034u

#define MAX_ORDINAL		256

static uint32_t
rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint32_t
rd32be(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static void
wr32(uint8_t *p, uint32_t v)
{
	p[0] = v;
	p[1] = v >> 8;
	p[2] = v >> 16;
	p[3] = v >> 24;
}

static bool
has_placeholder(const uint8_t *p, size_t n)
{
	static const char m[] = "@@HOMEBREW_";

	for (size_t i = 0; i + sizeof(m) - 1 <= n; i++)
		if (p[i] == '@' && memcmp(p + i, m, sizeof(m) - 1) == 0)
			return true;
	return false;
}

/* S with every placeholder replaced; a new string. */
static char *
replace_all(const char *s, size_t n)
{
	struct buf out = { 0 };

	for (size_t i = 0; i < n;) {
		size_t k, len = 0;

		for (k = 0; k < sizeof(placeholders) / sizeof(placeholders[0]); k++) {
			len = strlen(placeholders[k].from);
			if (i + len <= n && memcmp(s + i, placeholders[k].from, len) == 0)
				break;
		}
		if (k < sizeof(placeholders) / sizeof(placeholders[0])) {
			buf_addstr(&out, placeholders[k].to);
			i += len;
		} else
			buf_add(&out, s + i++, 1);
	}
	buf_add(&out, "", 0);
	return (char *)out.p;
}

/*
 * A text file's placeholders replaced (its length may change); a binary
 * file (a NUL in it) that has one is left alone, with a warning.
 */
int
relocate_text(struct buf *b, const char *path)
{
	char *s;

	if (!has_placeholder(b->p, b->n))
		return 0;
	if (memchr(b->p, 0, b->n) != NULL) {
		warnx_("%s: a binary file with a Homebrew placeholder in it, left as it is", path);
		return 0;
	}
	s = replace_all((const char *)b->p, b->n);
	buf_free(b);
	buf_addstr(b, s);
	free(s);
	return 0;
}

bool
is_macho(const struct buf *b)
{
	if (b->n < 32)
		return false;
	/* (CAFEBABE is a Java class file's magic too: its version, not a slice count.) */
	return rd32(b->p) == MH_MAGIC_64 ||
	    ((rd32be(b->p) == FAT_MAGIC || rd32be(b->p) == FAT_MAGIC_64) && rd32be(b->p + 4) < 20);
}

/* A fat file's arm64 slice, as a thin file in B; -1 if it has none. */
static int
thin(struct buf *b, const char *path)
{
	bool is64 = rd32be(b->p) == FAT_MAGIC_64;
	uint32_t n = rd32be(b->p + 4);
	size_t es = is64 ? 32 : 20;

	/* arm64 itself (subtype 0) first, then arm64e. */
	if (n == 0)
		goto none;
	for (uint32_t k = 0; k < 2 * n; k++) {
		uint32_t i = k % n;
		const uint8_t *a = b->p + 8 + i * es;
		uint64_t off, size;

		if (8 + (i + 1) * es > b->n)
			break;
		if (rd32be(a) != CPU_TYPE_ARM64 || ((rd32be(a + 4) & 0xffffff) == 0) != (k < n))
			continue;
		if (is64) {
			off = (uint64_t)rd32be(a + 8) << 32 | rd32be(a + 12);
			size = (uint64_t)rd32be(a + 16) << 32 | rd32be(a + 20);
		} else {
			off = rd32be(a + 8);
			size = rd32be(a + 12);
		}
		if (off + size > b->n || size < 32)
			break;
		struct buf t = { 0 };

		buf_add(&t, b->p + off, size);
		buf_free(b);
		*b = t;
		return 0;
	}
none:
	warnx_("%s: a universal file with no arm64 slice, left as it is", path);
	return -1;
}

static void
note_syslib(struct pkg *p, const char *name)
{
	if (strncmp(name, "/usr/lib/", 9) != 0 && strncmp(name, "/System/", 8) != 0)
		return;
	for (size_t i = 0; i < p->nsyslibs; i++)
		if (strcmp(p->syslibs[i], name) == 0)
			return;
	p->syslibs = realloc(p->syslibs, (p->nsyslibs + 1) * sizeof(char *));
	p->syslibs[p->nsyslibs++] = xstrdup(name);
}

static uint64_t
uleb(const uint8_t **p, const uint8_t *end)
{
	uint64_t v = 0;
	unsigned shift = 0;

	while (*p < end) {
		uint8_t c = *(*p)++;

		if (shift < 64)
			v |= (uint64_t)(c & 0x7f) << shift;
		shift += 7;
		if (!(c & 0x80))
			break;
	}
	return v;
}

/*
 * The library ordinals (1, 2, ...: the dylib load commands in order) the
 * file imports symbols from, in USED; false if that cannot be told (no
 * fixups we read, or a flat-namespace import, which any library may
 * serve).
 */
static bool
imported_ordinals(const struct buf *b, bool used[MAX_ORDINAL])
{
	uint32_t ncmds = rd32(b->p + 16), sizeofcmds = rd32(b->p + 20);
	const uint8_t *lc = b->p + 32, *end = b->p + 32 + sizeofcmds;
	bool known = false;

	memset(used, 0, MAX_ORDINAL * sizeof(bool));
	for (uint32_t i = 0; i < ncmds && end - lc >= 16; lc += rd32(lc + 4), i++) {
		uint32_t cmd = rd32(lc), size = rd32(lc + 4);

		if (size < 8 || size > (size_t)(end - lc))
			return false;
		if (cmd == LC_DYLD_CHAINED_FIXUPS) {
			uint32_t off = rd32(lc + 8), len = rd32(lc + 12);
			const uint8_t *h;

			if (off > b->n || len > b->n - off || len < 28)
				return false;
			h = b->p + off;
			uint32_t imports = rd32(h + 8), count = rd32(h + 16), format = rd32(h + 20);
			size_t es = format == 1 ? 4 : format == 2 ? 8 : format == 3 ? 16 : 0;

			if (es == 0 || imports > len || count > (len - imports) / es)
				return false;
			for (uint32_t k = 0; k < count; k++) {
				const uint8_t *e = h + imports + k * es;
				int ord;

				/* (the specials, -1 to -15, at the top of the range) */
				if (format == 3)
					ord = (rd32(e) & 0xffff) >= 0xfff0 ? (int16_t)(rd32(e) & 0xffff) : (int)(rd32(e) & 0xffff);
				else
					ord = (rd32(e) & 0xff) >= 0xf0 ? (int8_t)(rd32(e) & 0xff) : (int)(rd32(e) & 0xff);
				if (ord == -2)		/* flat lookup */
					return false;
				if (ord >= MAX_ORDINAL)
					return false;
				if (ord > 0)
					used[ord] = true;
			}
			known = true;
		} else if (cmd == LC_DYLD_INFO || cmd == LC_DYLD_INFO_ONLY) {
			if (size < 48)
				return false;
			/* bind and lazy bind: their SET_DYLIB_ORDINAL opcodes */
			for (int r = 0; r < 2; r++) {
				uint32_t off = rd32(lc + (r ? 40 : 16)), len = rd32(lc + (r ? 44 : 20));
				const uint8_t *p, *pe;

				if (off > b->n || len > b->n - off)
					return false;
				for (p = b->p + off, pe = p + len; p < pe;) {
					uint8_t op = *p & 0xf0, imm = *p & 0x0f;

					p++;
					switch (op) {
					case 0x10:	/* SET_DYLIB_ORDINAL_IMM */
						used[imm] = true;
						break;
					case 0x20: {	/* SET_DYLIB_ORDINAL_ULEB */
						uint64_t o = uleb(&p, pe);

						if (o >= MAX_ORDINAL)
							return false;
						used[o] = true;
						break;
					}
					case 0x30:	/* SET_DYLIB_SPECIAL_IMM */
						if (imm == 0x0e)	/* -2: flat lookup */
							return false;
						break;
					case 0x40:	/* SET_SYMBOL_TRAILING_FLAGS_IMM, a name */
						while (p < pe && *p++)
							;
						break;
					case 0x60: case 0x70: case 0x80: case 0xa0:	/* one LEB */
						uleb(&p, pe);
						break;
					case 0xc0:	/* DO_BIND_ULEB_TIMES_SKIPPING_ULEB */
						uleb(&p, pe);
						uleb(&p, pe);
						break;
					case 0xd0:	/* THREADED */
						if (imm == 0)
							uleb(&p, pe);
						break;
					}
				}
			}
			known = true;
		}
	}
	return known;
}

static bool
system_has(const char *lib)
{
	struct stat st;
	bool has = stat(lib, &st) == 0;

	return has;
}

/*
 * A Mach-O file relocated and re-signed: the arm64 slice of a universal
 * one; the strings of its dylib and rpath load commands with the
 * placeholders replaced, the load commands rebuilt (a longer string grows
 * its command into the padding after them); the /usr/lib and /System
 * libraries it loads noted in P, but for one the system lacks and the
 * file imports nothing from, which is weak-linked instead; then an ad-hoc
 * signature.
 */
int
macho_fix(struct buf *b, const char *path, struct pkg *p)
{
	uint32_t ncmds, sizeofcmds, filetype;
	uint64_t space = UINT64_MAX;
	struct buf cmds = { 0 };
	const uint8_t *lc;
	bool used[MAX_ORDINAL], known;
	int ordinal = 0;

	if (rd32(b->p) != MH_MAGIC_64 && thin(b, path) < 0)
		return 0;
	if (rd32(b->p + 4) != CPU_TYPE_ARM64) {
		warnx_("%s: not an arm64 Mach-O file, left as it is", path);
		return 0;
	}
	filetype = rd32(b->p + 12);
	ncmds = rd32(b->p + 16);
	sizeofcmds = rd32(b->p + 20);
	if (32 + (uint64_t)sizeofcmds > b->n) {
		warnx_("%s: a damaged Mach-O file", path);
		return -1;
	}
	/* The room for load commands: up to the first section's data. */
	lc = b->p + 32;
	for (uint32_t i = 0; i < ncmds; i++) {
		const uint8_t *end = b->p + 32 + sizeofcmds;
		uint32_t cmd, size;

		if (end - lc < 8 || (size = rd32(lc + 4)) < 8 || size > (size_t)(end - lc) ||
		    ((cmd = rd32(lc)) == LC_SEGMENT_64 && size < 72)) {
			warnx_("%s: a damaged load command", path);
			return -1;
		}
		if (cmd == LC_SEGMENT_64) {
			uint32_t nsects = rd32(lc + 64);

			for (uint32_t s = 0; s < nsects && 72 + (s + 1) * 80 <= size; s++) {
				const uint8_t *sect = lc + 72 + s * 80;
				uint32_t off = rd32(sect + 48), flags = rd32(sect + 64);
				uint32_t type = flags & 0xff;

				/* zerofill sections have no file data */
				if (off != 0 && type != 0x1 && type != 0xc && type != 0x12 && off < space)
					space = off;
			}
		}
		lc += size;
	}
	if (space == UINT64_MAX)
		space = b->n;
	known = imported_ordinals(b, used);

	lc = b->p + 32;
	for (uint32_t i = 0; i < ncmds; i++) {
		uint32_t cmd = rd32(lc), size = rd32(lc + 4), stroff = 0;

		switch (cmd) {
		case LC_ID_DYLIB: case LC_LOAD_DYLIB: case LC_LOAD_WEAK_DYLIB:
		case LC_REEXPORT_DYLIB: case LC_LAZY_LOAD_DYLIB: case LC_LOAD_UPWARD_DYLIB:
		case LC_RPATH:
			stroff = rd32(lc + 8);
			break;
		}
		if (stroff >= 12 && stroff < size) {
			const char *s = (const char *)lc + stroff;
			size_t slen = strnlen(s, size - stroff);
			char *ns = replace_all(s, slen);
			size_t nsize = (stroff + strlen(ns) + 1 + 7) & ~(size_t)7;
			uint8_t *c = xmalloc(nsize);
			bool sys = strncmp(ns, "/usr/lib/", 9) == 0 || strncmp(ns, "/System/", 8) == 0;

			if (cmd != LC_ID_DYLIB && cmd != LC_RPATH)
				ordinal++;
			memcpy(c, lc, stroff);
			if (cmd == LC_LOAD_DYLIB && sys && known && ordinal < MAX_ORDINAL && !used[ordinal] &&
			    !system_has(ns)) {
				warnx_("%s: weak-linked %s, which this system does not have and it imports nothing from",
				    path, ns);
				wr32(c, LC_LOAD_WEAK_DYLIB);
			} else if (cmd != LC_ID_DYLIB && cmd != LC_RPATH &&
			    (cmd != LC_LOAD_WEAK_DYLIB || !sys || system_has(ns)))
				note_syslib(p, ns);	/* (a weak one only if it is there) */
			wr32(c + 4, (uint32_t)nsize);
			memcpy(c + stroff, ns, strlen(ns));
			buf_add(&cmds, c, nsize);
			free(c);
			free(ns);
		} else
			buf_add(&cmds, lc, size);
		lc += size;
	}
	if (32 + cmds.n > space) {
		warnx_("%s: no room for the relocated load commands", path);
		buf_free(&cmds);
		return -1;
	}
	if (cmds.n != sizeofcmds || memcmp(cmds.p, b->p + 32, cmds.n) != 0) {
		memset(b->p + 32, 0, (cmds.n > sizeofcmds ? cmds.n : sizeofcmds));
		memcpy(b->p + 32, cmds.p, cmds.n);
		wr32(b->p + 20, (uint32_t)cmds.n);
	}
	buf_free(&cmds);
	if (filetype == MH_OBJECT)
		return 0;
	return codesign_adhoc(b, path);
}
