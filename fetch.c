/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Piebrew authors
 *
 * HTTP(S) GETs into memory with libcurl: redirects followed (ghcr.io
 * hands a blob on to its CDN; curl sends the bearer token to ghcr.io
 * alone), the CA bundle libcurl was built with.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>

#include "piebrew.h"

static size_t
write_cb(char *p, size_t size, size_t n, void *b)
{
	buf_add(b, p, size * n);
	return size * n;
}

static int
progress_cb(void *name, curl_off_t total, curl_off_t now, curl_off_t ut, curl_off_t un)
{
	(void)ut;
	(void)un;
	if (total > 0)
		fprintf(stderr, "\r%s: %lld of %lld KiB", (const char *)name,
		    (long long)now / 1024, (long long)total / 1024);
	return 0;
}

int
fetch(const char *url, const char *bearer, bool progress, struct buf *out)
{
	static bool inited;
	struct curl_slist *h = NULL;
	char errbuf[CURL_ERROR_SIZE] = "";
	long status = 0;
	CURLcode rc;
	CURL *c;
	char *auth = NULL;

	if (!inited) {
		curl_global_init(CURL_GLOBAL_DEFAULT);
		inited = true;
	}
	if (verbose)
		fprintf(stderr, "piebrew: GET %s\n", url);
	c = curl_easy_init();
	curl_easy_setopt(c, CURLOPT_URL, url);
	curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(c, CURLOPT_MAXREDIRS, 10L);
	curl_easy_setopt(c, CURLOPT_USERAGENT, "piebrew/" PIEBREW_VERSION);
	curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(c, CURLOPT_WRITEDATA, out);
	curl_easy_setopt(c, CURLOPT_ERRORBUFFER, errbuf);
	curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 30L);
	curl_easy_setopt(c, CURLOPT_LOW_SPEED_LIMIT, 1L);
	curl_easy_setopt(c, CURLOPT_LOW_SPEED_TIME, 60L);
	if (bearer) {
		auth = xasprintf("Authorization: Bearer %s", bearer);
		h = curl_slist_append(h, auth);
	}
	h = curl_slist_append(h, "Accept: application/json, application/octet-stream, */*");
	curl_easy_setopt(c, CURLOPT_HTTPHEADER, h);
	if (progress && isatty(STDERR_FILENO)) {
		curl_easy_setopt(c, CURLOPT_NOPROGRESS, 0L);
		curl_easy_setopt(c, CURLOPT_XFERINFOFUNCTION, progress_cb);
		curl_easy_setopt(c, CURLOPT_XFERINFODATA, (void *)"bottle");
	}
	rc = curl_easy_perform(c);
	curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
	if (progress && isatty(STDERR_FILENO))
		fprintf(stderr, "\r\033[K");
	curl_easy_cleanup(c);
	curl_slist_free_all(h);
	free(auth);
	if (rc != CURLE_OK) {
		fprintf(stderr, "piebrew: %s: %s\n", url, errbuf[0] ? errbuf : curl_easy_strerror(rc));
		return -1;
	}
	if (status != 200) {
		fprintf(stderr, "piebrew: %s: HTTP %ld\n", url, status);
		return (int)status;
	}
	return 0;
}
