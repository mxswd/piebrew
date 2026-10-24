/*
 * SPDX-License-Identifier: BSD-2-Clause
 * Copyright (c) 2026 The Piebrew authors
 *
 * Buffers, digests, running programs.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <openssl/evp.h>

#include "piebrew.h"

extern char **environ;
int verbose;

void *
xmalloc(size_t n)
{
	void *p = calloc(1, n ? n : 1);

	if (p == NULL)
		err(1, "malloc");
	return p;
}

char *
xstrdup(const char *s)
{
	char *p = strdup(s ? s : "");

	if (p == NULL)
		err(1, "strdup");
	return p;
}

char *
xasprintf(const char *fmt, ...)
{
	va_list ap;
	char *s;

	va_start(ap, fmt);
	if (vasprintf(&s, fmt, ap) < 0)
		err(1, "asprintf");
	va_end(ap);
	return s;
}

void
warnx_(const char *fmt, ...)
{
	va_list ap;

	fputs("piebrew: warning: ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

void
buf_add(struct buf *b, const void *p, size_t n)
{
	if (b->n + n + 1 > b->cap) {
		size_t cap = b->cap ? b->cap : 4096;

		while (b->n + n + 1 > cap)
			cap *= 2;
		if ((b->p = realloc(b->p, cap)) == NULL)
			err(1, "realloc");
		b->cap = cap;
	}
	if (n)
		memcpy(b->p + b->n, p, n);
	b->n += n;
	b->p[b->n] = 0;		/* always NUL-terminated, for text */
}

void
buf_addstr(struct buf *b, const char *s)
{
	buf_add(b, s, strlen(s));
}

void
buf_printf(struct buf *b, const char *fmt, ...)
{
	va_list ap;
	char *s;

	va_start(ap, fmt);
	if (vasprintf(&s, fmt, ap) < 0)
		err(1, "asprintf");
	va_end(ap);
	buf_addstr(b, s);
	free(s);
}

void
buf_free(struct buf *b)
{
	free(b->p);
	memset(b, 0, sizeof(*b));
}

static void
digest_hex(const EVP_MD *md, const void *p, size_t n, char *out)
{
	unsigned char d[EVP_MAX_MD_SIZE];
	unsigned int len;

	if (!EVP_Digest(p, n, d, &len, md, NULL))
		errx(1, "EVP_Digest failed");
	for (unsigned i = 0; i < len; i++)
		sprintf(out + 2 * i, "%02x", d[i]);
}

void
sha256_hex(const void *p, size_t n, char out[65])
{
	digest_hex(EVP_sha256(), p, n, out);
}

void
md5_hex(const void *p, size_t n, char out[33])
{
	digest_hex(EVP_md5(), p, n, out);
}

/*
 * Run ARGV (found on PATH) and wait for it; with OUT, its standard output
 * goes there, and its standard error to /dev/null (the queries' "no
 * packages found"). Returns its exit status, or -1 if it could not be run
 * or was killed.
 */
int
run(char *const argv[], struct buf *out)
{
	posix_spawn_file_actions_t fa;
	int fds[2] = { -1, -1 }, st;
	pid_t pid;

	if (verbose) {
		fprintf(stderr, "+");
		for (int i = 0; argv[i]; i++)
			fprintf(stderr, " %s", argv[i]);
		fprintf(stderr, "\n");
	}
	posix_spawn_file_actions_init(&fa);
	if (out) {
		if (pipe(fds) < 0)
			err(1, "pipe");
		posix_spawn_file_actions_adddup2(&fa, fds[1], STDOUT_FILENO);
		posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
		posix_spawn_file_actions_addclose(&fa, fds[0]);
		posix_spawn_file_actions_addclose(&fa, fds[1]);
	}
	errno = posix_spawnp(&pid, argv[0], &fa, NULL, argv, environ);
	posix_spawn_file_actions_destroy(&fa);
	if (errno) {
		warn("%s", argv[0]);
		if (out) {
			close(fds[0]);
			close(fds[1]);
		}
		return -1;
	}
	if (out) {
		char tmp[8192];
		ssize_t r;

		close(fds[1]);
		while ((r = read(fds[0], tmp, sizeof(tmp))) > 0 || (r < 0 && errno == EINTR))
			if (r > 0)
				buf_add(out, tmp, (size_t)r);
		close(fds[0]);
	}
	while (waitpid(pid, &st, 0) < 0)
		if (errno != EINTR)
			err(1, "waitpid");
	return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}
