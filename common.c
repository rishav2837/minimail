/* common.c - socket I/O helpers and protocol field utilities */
#define _GNU_SOURCE
#include "common.h"
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

void conn_init(conn_t *c, int fd) { c->fd = fd; c->len = 0; }

int send_all(int fd, const char *buf, size_t n)
{
    size_t sent = 0;
    while (sent < n) {
        /* MSG_NOSIGNAL: a closed peer gives EPIPE instead of killing us */
        ssize_t r = send(fd, buf + sent, n - sent, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        sent += (size_t)r;
    }
    return 0;
}

int send_line(conn_t *c, const char *fmt, ...)
{
    char buf[MAX_LINE + 1];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, MAX_LINE, fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if (n >= MAX_LINE) n = MAX_LINE - 1;       /* truncated: still terminate */
    buf[n++] = '\n';
    return send_all(c->fd, buf, (size_t)n);
}

int conn_readline(conn_t *c, char *out, size_t outsz)
{
    for (;;) {
        char *nl = memchr(c->buf, '\n', c->len);
        if (nl) {
            size_t n = (size_t)(nl - c->buf);
            if (n >= outsz) n = outsz - 1;
            memcpy(out, c->buf, n);
            out[n] = '\0';
            if (n && out[n - 1] == '\r') out[n - 1] = '\0';
            size_t rest = c->len - (size_t)(nl - c->buf) - 1;
            memmove(c->buf, nl + 1, rest);
            c->len = rest;
            return RL_OK;
        }
        if (c->len >= sizeof c->buf) { c->len = 0; return RL_TOOLONG; }
        ssize_t r = recv(c->fd, c->buf + c->len, sizeof c->buf - c->len, 0);
        if (r == 0) return RL_CLOSED;
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return RL_TIMEOUT;
            return RL_CLOSED;
        }
        c->len += (size_t)r;
    }
}

int esc(const char *in, char *out, size_t outsz)
{
    size_t o = 0;
    for (; *in; in++) {
        const char *rep = NULL;
        char one[2] = { *in, 0 };
        if (*in == '\\') rep = "\\\\";
        else if (*in == '|') rep = "\\p";
        else if (*in == '\n') rep = "\\n";
        else if (*in == '\r') continue;
        else rep = one;
        size_t l = strlen(rep);
        if (o + l + 1 > outsz) return -1;
        memcpy(out + o, rep, l);
        o += l;
    }
    if (o + 1 > outsz) return -1;
    out[o] = '\0';
    return 0;
}

void unesc(char *s)
{
    char *r = s, *w = s;
    while (*r) {
        if (*r == '\\' && r[1]) {
            r++;
            if (*r == 'p') *w++ = '|';
            else if (*r == 'n') *w++ = '\n';
            else *w++ = *r;                 /* "\\\\" -> '\\', unknown -> literal */
            r++;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
}

int split_fields(char *line, char **f, int max)
{
    int n = 0;
    f[n++] = line;
    for (char *p = line; *p; p++) {
        if (*p == '|') {
            if (n >= max) return -1;
            *p = '\0';
            f[n++] = p + 1;
        }
    }
    return n;
}

void trim(char *s)
{
    size_t l = strlen(s), a = 0;
    while (l > 0 && isspace((unsigned char)s[l - 1])) s[--l] = '\0';
    while (s[a] && isspace((unsigned char)s[a])) a++;
    if (a) memmove(s, s + a, strlen(s + a) + 1);
}

void to_lower(char *s) { for (; *s; s++) *s = (char)tolower((unsigned char)*s); }

int is_valid_username(const char *s)
{
    size_t l = strlen(s);
    if (l < USER_MIN || l > USER_MAX) return 0;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && *s != '_') return 0;  /* no '/', '.', so no path tricks */
    return 1;
}

int is_valid_email(const char *s)
{
    size_t l = strlen(s);
    if (l < 5 || l > EMAIL_MAX) return 0;
    const char *at = strchr(s, '@');
    if (!at || at == s || strchr(at + 1, '@')) return 0;
    if (!strchr(at + 1, '.') || at[1] == '.' || s[l - 1] == '.') return 0;
    for (; *s; s++)
        if (!isalnum((unsigned char)*s) && !strchr("@._-+", *s)) return 0;
    return 1;
}
