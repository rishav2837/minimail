/* common.h - definitions shared by the MiniMail server and client */
#ifndef COMMON_H
#define COMMON_H

#include <stddef.h>

#define DEFAULT_PORT   5000
#define MAX_LINE       16384   /* max length of one protocol line (incl. '\n') */
#define USER_MAX       32
#define USER_MIN       3
#define EMAIL_MAX      64
#define PASS_MIN       6
#define PASS_MAX       64
#define SUBJECT_MAX    100
#define BODY_MAX       4096
#define MAX_RCPT       10

/* A buffered connection: TCP is a byte stream, so one recv() may return half a
 * line or several lines. conn_t keeps the leftover bytes between calls. */
typedef struct {
    int    fd;
    char   buf[MAX_LINE];
    size_t len;
} conn_t;

/* conn_readline() return codes */
#define RL_OK        0
#define RL_CLOSED   -1   /* peer closed or fatal socket error */
#define RL_TOOLONG  -2   /* line exceeded MAX_LINE */
#define RL_TIMEOUT  -3   /* SO_RCVTIMEO expired */

void conn_init(conn_t *c, int fd);
int  conn_readline(conn_t *c, char *out, size_t outsz);   /* strips \r\n */
int  send_all(int fd, const char *buf, size_t n);          /* loops until done */
int  send_line(conn_t *c, const char *fmt, ...);           /* appends '\n' */

/* Field escaping: '\\' -> "\\\\", '|' -> "\\p", newline -> "\\n", CR dropped */
int  esc(const char *in, char *out, size_t outsz);         /* 0 ok, -1 overflow */
void unesc(char *s);                                       /* in place */
int  split_fields(char *line, char **f, int max);          /* -1 if too many */

void trim(char *s);
void to_lower(char *s);
int  is_valid_username(const char *s);
int  is_valid_email(const char *s);

#endif
