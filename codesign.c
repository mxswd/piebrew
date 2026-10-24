/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Piebrew authors
 *
 * An ad-hoc code signature, as `codesign -s -` makes: a CodeDirectory of
 * SHA-256 page hashes, an empty requirement set and an empty CMS blob,
 * plus the entitlements the old signature had. The pages are 4 KB: a
 * kernel with 4 KB pages (the BCM2711's) takes no other size, one with
 * 16 KB pages takes 4 KB ones too. The signature goes where the old one
 * was (LC_CODE_SIGNATURE's offset, at the end of __LINKEDIT and of the
 * file), or one is added after __LINKEDIT's data.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#include "piebrew.h"

#define MH_EXECUTE		0x2
#define LC_SEGMENT_64		0x19
#define LC_CODE_SIGNATURE	0x1d

#define CSMAGIC_EMBEDDED_SIGNATURE	0xfade0cc0u
#define CSMAGIC_CODEDIRECTORY		0xfade0c02u
#define CSMAGIC_REQUIREMENTS		0xfade0c01u
#define CSMAGIC_BLOBWRAPPER		0xfade0b01u
#define CSSLOT_CODEDIRECTORY		0
#define CSSLOT_REQUIREMENTS		2
#define CSSLOT_ENTITLEMENTS		5
#define CSSLOT_DER_ENTITLEMENTS		7
#define CSSLOT_SIGNATURESLOT		0x10000
#define CS_ADHOC			0x2
#define CS_RUNTIME			0x10000
#define CS_LINKER_SIGNED		0x20000
#define CS_EXECSEG_MAIN_BINARY		0x1
#define CS_HASHTYPE_SHA256		2

#define PAGE_SHIFT	12
#define PAGE		(1u << PAGE_SHIFT)
#define CD_HEADER	88	/* version 0x20400: through execSegFlags */

static uint32_t
rd32(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t
rd64(const uint8_t *p)
{
	return rd32(p) | (uint64_t)rd32(p + 4) << 32;
}

static void
wr32(uint8_t *p, uint32_t v)
{
	for (int i = 0; i < 4; i++)
		p[i] = v >> (8 * i);
}

static void
wr64(uint8_t *p, uint64_t v)
{
	wr32(p, (uint32_t)v);
	wr32(p + 4, (uint32_t)(v >> 32));
}

static uint32_t
be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

static void
put32(struct buf *b, uint32_t v)
{
	uint8_t x[4] = { v >> 24, v >> 16, v >> 8, v };

	buf_add(b, x, 4);
}

static void
put64(struct buf *b, uint64_t v)
{
	put32(b, (uint32_t)(v >> 32));
	put32(b, (uint32_t)v);
}

static void
sha256(const void *p, size_t n, uint8_t out[32])
{
	unsigned len;

	EVP_Digest(p, n, out, &len, EVP_sha256(), NULL);
}

/* What the old signature had that we keep. */
struct old {
	char ident[256];
	uint32_t flags;
	const uint8_t *ent, *der;
	uint32_t entlen, derlen;
};

static void
read_old(const uint8_t *sig, size_t n, struct old *o)
{
	if (n < 12 || be32(sig) != CSMAGIC_EMBEDDED_SIGNATURE)
		return;
	uint32_t count = be32(sig + 8);

	for (uint32_t i = 0; i < count && 12 + (i + 1) * 8 <= n; i++) {
		uint32_t type = be32(sig + 12 + i * 8), off = be32(sig + 16 + i * 8);
		const uint8_t *blob;
		uint32_t len;

		if (off > n || n - off < 8)
			continue;
		blob = sig + off;
		if ((len = be32(blob + 4)) < 8 || len > n - off)
			continue;
		if (type == CSSLOT_CODEDIRECTORY && be32(blob) == CSMAGIC_CODEDIRECTORY && len >= 44) {
			uint32_t identoff = be32(blob + 20);

			o->flags = be32(blob + 12);
			if (identoff < len) {
				size_t l = strnlen((const char *)blob + identoff, len - identoff);

				if (l < sizeof(o->ident)) {
					memcpy(o->ident, blob + identoff, l);
					o->ident[l] = 0;
				}
			}
		} else if (type == CSSLOT_ENTITLEMENTS) {
			o->ent = blob;
			o->entlen = len;
		} else if (type == CSSLOT_DER_ENTITLEMENTS) {
			o->der = blob;
			o->derlen = len;
		}
	}
}

int
codesign_adhoc(struct buf *b, const char *path)
{
	uint32_t ncmds = rd32(b->p + 16), sizeofcmds = rd32(b->p + 20), filetype = rd32(b->p + 12);
	uint8_t *lc = b->p + 32, *cs = NULL, *linkedit = NULL, *end = b->p + 32 + sizeofcmds;
	uint64_t textoff = 0, textsize = 0, dataoff;
	struct old old = { .flags = 0 };
	struct buf oldsig = { 0 }, cd = { 0 }, req = { 0 }, sig = { 0 };

	if (32 + (uint64_t)sizeofcmds > b->n) {
		warnx_("%s: a damaged Mach-O file, not signed", path);
		return -1;
	}
	for (uint32_t i = 0; i < ncmds; i++) {
		uint32_t cmd, size;

		if (end - lc < 8 || (size = rd32(lc + 4)) < 8 || size > (size_t)(end - lc) ||
		    ((cmd = rd32(lc)) == LC_SEGMENT_64 && size < 72) || (cmd == LC_CODE_SIGNATURE && size < 16)) {
			warnx_("%s: a damaged load command, not signed", path);
			return -1;
		}

		if (cmd == LC_CODE_SIGNATURE)
			cs = lc;
		else if (cmd == LC_SEGMENT_64 && strncmp((char *)lc + 8, "__TEXT", 16) == 0) {
			textoff = rd64(lc + 40);
			textsize = rd64(lc + 48);
		} else if (cmd == LC_SEGMENT_64 && strncmp((char *)lc + 8, "__LINKEDIT", 16) == 0)
			linkedit = lc;
		lc += size;
	}
	if (linkedit == NULL) {
		warnx_("%s: no __LINKEDIT segment, not signed", path);
		return -1;
	}
	if (cs != NULL) {
		dataoff = rd32(cs + 8);
		uint32_t datasize = rd32(cs + 12);

		if (dataoff + (uint64_t)datasize > b->n || dataoff < rd64(linkedit + 40)) {
			warnx_("%s: the code signature is not in __LINKEDIT, at the end of the file", path);
			return -1;
		}
		/* A copy: B's tail is about to be replaced. */
		buf_add(&oldsig, b->p + dataoff, datasize);
		read_old(oldsig.p, oldsig.n, &old);
	} else {
		/* A new LC_CODE_SIGNATURE in the padding after the load commands. */
		uint64_t first = UINT64_MAX;

		lc = b->p + 32;
		for (uint32_t i = 0; i < ncmds; i++) {
			if (rd32(lc) == LC_SEGMENT_64) {
				uint32_t size = rd32(lc + 4);

				for (uint32_t s = 0; s < rd32(lc + 64) && 72 + (s + 1) * 80 <= size; s++) {
					uint32_t off = rd32(lc + 72 + s * 80 + 48);
					uint32_t type = rd32(lc + 72 + s * 80 + 64) & 0xff;

					if (off && type != 0x1 && type != 0xc && type != 0x12 && off < first)
						first = off;
				}
			}
			lc += rd32(lc + 4);
		}
		if (32 + (uint64_t)sizeofcmds + 16 > first) {
			warnx_("%s: no room for a code signature load command, not signed", path);
			return -1;
		}
		cs = b->p + 32 + sizeofcmds;
		wr32(cs, LC_CODE_SIGNATURE);
		wr32(cs + 4, 16);
		wr32(b->p + 16, ncmds + 1);
		wr32(b->p + 20, sizeofcmds + 16);
		dataoff = rd64(linkedit + 40) + rd64(linkedit + 48);
		dataoff = (dataoff + 15) & ~(uint64_t)15;
		if (dataoff > b->n + 16 || b->n > dataoff) {
			warnx_("%s: __LINKEDIT is not what ends the file, not signed", path);
			return -1;
		}
		wr32(cs + 8, (uint32_t)dataoff);
	}
	if (old.ident[0] == 0) {
		const char *base = strrchr(path, '/');

		snprintf(old.ident, sizeof(old.ident), "%s", base ? base + 1 : path);
	}

	/* The sizes first: the header is in the pages hashed. */
	uint32_t ncode = (uint32_t)((dataoff + PAGE - 1) / PAGE);
	uint32_t nspecial = old.der ? CSSLOT_DER_ENTITLEMENTS : old.ent ? CSSLOT_ENTITLEMENTS : CSSLOT_REQUIREMENTS;
	size_t identlen = strlen(old.ident) + 1;
	uint32_t cdlen = (uint32_t)(CD_HEADER + identlen + (size_t)(nspecial + ncode) * 32);
	uint32_t nblobs = 3 + (old.ent != NULL) + (old.der != NULL);
	uint32_t siglen = 12 + nblobs * 8 + cdlen + 12 + old.entlen + old.derlen + 8;
	uint32_t datasize = (siglen + 15) & ~15u;
	uint64_t ledoff = rd64(linkedit + 40), ledsize = dataoff + datasize - ledoff;

	wr32(cs + 12, datasize);
	wr64(linkedit + 48, ledsize);					/* filesize */
	wr64(linkedit + 32, (ledsize + 0x3fff) & ~(uint64_t)0x3fff);	/* vmsize */

	/* The file up to the signature, zero-padded to it. */
	if (b->n > dataoff)
		b->n = dataoff;
	while (b->n < dataoff)
		buf_add(b, "", 1);

	put32(&req, CSMAGIC_REQUIREMENTS);
	put32(&req, 12);
	put32(&req, 0);

	put32(&cd, CSMAGIC_CODEDIRECTORY);
	put32(&cd, cdlen);
	put32(&cd, 0x20400);					/* version */
	/* (CS_RUNTIME wants version 0x20500's runtime field: dropped, as ad hoc.) */
	put32(&cd, (old.flags & ~(uint32_t)(CS_LINKER_SIGNED | CS_RUNTIME)) | CS_ADHOC);
	put32(&cd, (uint32_t)(CD_HEADER + identlen + nspecial * 32));	/* hashOffset */
	put32(&cd, CD_HEADER);					/* identOffset */
	put32(&cd, nspecial);
	put32(&cd, ncode);
	put32(&cd, (uint32_t)dataoff);				/* codeLimit */
	uint8_t hb[4] = { 32, CS_HASHTYPE_SHA256, 0, PAGE_SHIFT };
	buf_add(&cd, hb, 4);					/* hashSize, hashType, platform, pageSize */
	put32(&cd, 0);						/* spare2 */
	put32(&cd, 0);						/* scatterOffset */
	put32(&cd, 0);						/* teamOffset */
	put32(&cd, 0);						/* spare3 */
	put64(&cd, 0);						/* codeLimit64 */
	put64(&cd, textoff);					/* execSegBase */
	put64(&cd, textsize);					/* execSegLimit */
	put64(&cd, filetype == MH_EXECUTE ? CS_EXECSEG_MAIN_BINARY : 0);
	buf_add(&cd, old.ident, identlen);
	/* Special slots, highest first: slot -n at hashOffset - n * 32. */
	for (uint32_t s = nspecial; s >= 1; s--) {
		uint8_t h[32] = { 0 };

		if (s == CSSLOT_REQUIREMENTS)
			sha256(req.p, req.n, h);
		else if (s == CSSLOT_ENTITLEMENTS && old.ent)
			sha256(old.ent, old.entlen, h);
		else if (s == CSSLOT_DER_ENTITLEMENTS && old.der)
			sha256(old.der, old.derlen, h);
		buf_add(&cd, h, 32);
	}
	for (uint32_t i = 0; i < ncode; i++) {
		uint64_t off = (uint64_t)i * PAGE;
		size_t len = dataoff - off < PAGE ? dataoff - off : PAGE;
		uint8_t h[32];

		sha256(b->p + off, len, h);
		buf_add(&cd, h, 32);
	}

	put32(&sig, CSMAGIC_EMBEDDED_SIGNATURE);
	put32(&sig, siglen);
	put32(&sig, nblobs);
	uint32_t off = 12 + nblobs * 8;
	put32(&sig, CSSLOT_CODEDIRECTORY);
	put32(&sig, off);
	off += cdlen;
	put32(&sig, CSSLOT_REQUIREMENTS);
	put32(&sig, off);
	off += 12;
	if (old.ent) {
		put32(&sig, CSSLOT_ENTITLEMENTS);
		put32(&sig, off);
		off += old.entlen;
	}
	if (old.der) {
		put32(&sig, CSSLOT_DER_ENTITLEMENTS);
		put32(&sig, off);
		off += old.derlen;
	}
	put32(&sig, CSSLOT_SIGNATURESLOT);
	put32(&sig, off);
	buf_add(&sig, cd.p, cd.n);
	buf_add(&sig, req.p, req.n);
	if (old.ent)
		buf_add(&sig, old.ent, old.entlen);
	if (old.der)
		buf_add(&sig, old.der, old.derlen);
	put32(&sig, CSMAGIC_BLOBWRAPPER);
	put32(&sig, 8);
	while (sig.n < datasize)
		buf_add(&sig, "", 1);

	buf_add(b, sig.p, sig.n);
	buf_free(&sig);
	buf_free(&cd);
	buf_free(&req);
	buf_free(&oldsig);
	return 0;
}
