/* server.c - MiniMail multi-client email server (pthread, one thread per client)
 *
 * Usage: ./server [-p port] [-d datadir] [-a bind_ip]
 * Storage: <datadir>/users.dat, <datadir>/mail/<user>/inbox.dat, sent.dat
 */
#define _GNU_SOURCE
#include "common.h"
#include <arpa/inet.h>
#include <crypt.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MAX_CLIENTS   100
#define IDLE_TIMEOUT  300          /* seconds of silence before we drop a client */
#define MAX_FIELDS    8

static char  g_datadir[256] = "data";
static volatile sig_atomic_t g_stop = 0;
static int   g_nclients = 0;
static char  g_active[MAX_CLIENTS][USER_MAX + 1];   /* logged-in usernames */
static pthread_mutex_t g_store = PTHREAD_MUTEX_INITIALIZER;  /* all file access */
static pthread_mutex_t g_sess  = PTHREAD_MUTEX_INITIALIZER;  /* sessions + counter */

typedef struct {
    conn_t c;
    char   user[USER_MAX + 1];     /* empty string = not logged in */
    char   peer[64];
} session_t;

/* ---------- logging ---------- */
static void logmsg(const session_t *s, const char *fmt, ...)
{
    char ts[32], msg[512];
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tm);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    fprintf(stderr, "[%s] [%s] %s\n", ts, s ? s->peer : "server", msg);
}

static void now_str(char *out, size_t n)
{
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(out, n, "%Y-%m-%d %H:%M:%S", &tm);
}

/* ---------- paths / low level storage ---------- */
static void path_users(char *p, size_t n) { snprintf(p, n, "%s/users.dat", g_datadir); }
static void path_box(char *p, size_t n, const char *user, const char *which)
{
    snprintf(p, n, "%s/mail/%s/%s.dat", g_datadir, user, which);
}

static int append_line(const char *path, const char *line)
{
    FILE *f = fopen(path, "a");
    if (!f) return -1;
    if (fprintf(f, "%s\n", line) < 0 || fflush(f) != 0) { fclose(f); return -1; }
    return fclose(f) == 0 ? 0 : -1;
}

/* ---------- users (caller must hold g_store) ---------- */
/* 1 = found, 0 = not found, -1 = I/O error */
static int user_lookup(const char *name, const char *email, char *hash_out, size_t hn)
{
    char path[600], line[1024];
    path_users(path, sizeof path);
    FILE *f = fopen(path, "r");
    if (!f) return errno == ENOENT ? 0 : -1;
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *fld[4];
        if (split_fields(line, fld, 4) != 3) continue;      /* user|email|hash */
        if ((name && strcmp(fld[0], name) == 0) || (email && strcmp(fld[1], email) == 0)) {
            found = 1;
            if (hash_out) snprintf(hash_out, hn, "%s", fld[2]);
            break;
        }
    }
    fclose(f);
    return found;
}

static int hash_password(const char *pw, char *out, size_t outsz)
{
    static const char cs[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    unsigned char rnd[16];
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(rnd, 1, sizeof rnd, f) != sizeof rnd) { if (f) fclose(f); return -1; }
    fclose(f);
    char salt[32] = "$6$";                         /* SHA-512 crypt with random salt */
    for (int i = 0; i < 16; i++) salt[3 + i] = cs[rnd[i] % 64];
    salt[19] = '$'; salt[20] = '\0';
    struct crypt_data *d = calloc(1, sizeof *d);
    if (!d) return -1;
    char *h = crypt_r(pw, salt, d);
    int rc = (h && h[0] != '*' && strlen(h) < outsz) ? (snprintf(out, outsz, "%s", h), 0) : -1;
    free(d);
    return rc;
}

static int verify_password(const char *pw, const char *stored)
{
    struct crypt_data *d = calloc(1, sizeof *d);
    if (!d) return 0;
    char *h = crypt_r(pw, stored, d);
    int ok = 0;
    if (h && strlen(h) == strlen(stored)) {          /* constant-time compare */
        unsigned char diff = 0;
        for (size_t i = 0; stored[i]; i++) diff |= (unsigned char)(h[i] ^ stored[i]);
        ok = (diff == 0);
    }
    free(d);
    return ok;
}

/* ---------- mailbox helpers (caller must hold g_store) ---------- */
static int next_id(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return 1;
    char line[MAX_LINE * 2];
    int max = 0;
    while (fgets(line, sizeof line, f)) {
        int id = atoi(line);
        if (id > max) max = id;
    }
    fclose(f);
    return max + 1;
}

/* Find record with given id. 1 found (line/fields filled), 0 none, -1 error. */
static int find_record(const char *path, int id, int nf, char *line, size_t ln, char **fld)
{
    FILE *f = fopen(path, "r");
    if (!f) return errno == ENOENT ? 0 : -1;
    int found = 0;
    while (fgets(line, (int)ln, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        if (atoi(line) != id) continue;
        if (split_fields(line, fld, nf) == nf) { found = 1; break; }
    }
    fclose(f);
    return found;
}

static int mark_read(const char *path, int id)
{
    char tmp[640], line[MAX_LINE * 2], copy[MAX_LINE * 2];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *in = fopen(path, "r"), *out = fopen(tmp, "w");
    if (!in || !out) { if (in) fclose(in); if (out) fclose(out); return -1; }
    while (fgets(line, sizeof line, in)) {
        line[strcspn(line, "\r\n")] = '\0';
        snprintf(copy, sizeof copy, "%s", line);
        char *f[8];
        if (atoi(line) == id && split_fields(copy, f, 7) == 7) {
            fprintf(out, "%s|%s|%s|%s|%s|R|%s\n", f[0], f[1], f[2], f[3], f[4], f[6]);
        } else {
            fprintf(out, "%s\n", line);
        }
    }
    fclose(in);
    if (fclose(out) != 0) { remove(tmp); return -1; }
    return rename(tmp, path);
}

/* ---------- sessions ---------- */
static int session_add(const char *user)
{
    int ok = 0, free_slot = -1;
    pthread_mutex_lock(&g_sess);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_active[i][0] && strcmp(g_active[i], user) == 0) { free_slot = -2; break; }
        if (!g_active[i][0] && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) { snprintf(g_active[free_slot], USER_MAX + 1, "%.32s", user); ok = 1; }
    pthread_mutex_unlock(&g_sess);
    return ok;
}

static void session_remove(const char *user)
{
    pthread_mutex_lock(&g_sess);
    for (int i = 0; i < MAX_CLIENTS; i++)
        if (strcmp(g_active[i], user) == 0) g_active[i][0] = '\0';
    pthread_mutex_unlock(&g_sess);
}

/* ---------- command handlers ---------- */
#define ERR(s, code, msg) send_line(&(s)->c, "ERR|%s|%s", code, msg)

static void cmd_register(session_t *s, char **f)
{
    char user[MAX_LINE / 4], email[MAX_LINE / 4], pass[MAX_LINE / 4];
    snprintf(user, sizeof user, "%s", f[1]);  unesc(user);  trim(user);  to_lower(user);
    snprintf(email, sizeof email, "%s", f[2]); unesc(email); trim(email); to_lower(email);
    snprintf(pass, sizeof pass, "%s", f[3]);  unesc(pass);

    if (s->user[0])                       { ERR(s, "ALREADY_LOGGED_IN", "Log out before registering"); return; }
    if (!is_valid_username(user))         { ERR(s, "BAD_USERNAME", "Username must be 3-32 letters, digits or underscore"); return; }
    if (!is_valid_email(email))           { ERR(s, "BAD_EMAIL", "Invalid email address"); return; }
    if (strlen(pass) < PASS_MIN || strlen(pass) > PASS_MAX) { ERR(s, "BAD_PASSWORD", "Password must be 6-64 characters"); return; }

    char hash[256], esc_hash[512], line[8192], path[600], dir[600];
    pthread_mutex_lock(&g_store);
    int a = user_lookup(user, NULL, NULL, 0);
    int b = a == 0 ? user_lookup(NULL, email, NULL, 0) : 0;
    if (a < 0 || b < 0) { pthread_mutex_unlock(&g_store); ERR(s, "STORAGE", "Cannot read user database"); return; }
    if (a == 1) { pthread_mutex_unlock(&g_store); ERR(s, "DUPLICATE_USER", "Username already registered"); return; }
    if (b == 1) { pthread_mutex_unlock(&g_store); ERR(s, "DUPLICATE_EMAIL", "Email address already registered"); return; }
    if (hash_password(pass, hash, sizeof hash) != 0 || esc(hash, esc_hash, sizeof esc_hash) != 0) {
        pthread_mutex_unlock(&g_store); ERR(s, "STORAGE", "Password hashing failed"); return;
    }
    snprintf(dir, sizeof dir, "%s/mail/%s", g_datadir, user);
    path_users(path, sizeof path);
    snprintf(line, sizeof line, "%.32s|%.64s|%.500s", user, email, esc_hash);
    if ((mkdir(dir, 0700) != 0 && errno != EEXIST) || append_line(path, line) != 0) {
        pthread_mutex_unlock(&g_store); ERR(s, "STORAGE", "Cannot write user database"); return;
    }
    pthread_mutex_unlock(&g_store);
    logmsg(s, "REGISTER ok user=%s", user);
    send_line(&s->c, "OK|REGISTERED|Account created");
}

static void cmd_login(session_t *s, char **f)
{
    char user[MAX_LINE / 4], pass[MAX_LINE / 4], hash[256];
    snprintf(user, sizeof user, "%s", f[1]); unesc(user); trim(user); to_lower(user);
    snprintf(pass, sizeof pass, "%s", f[2]); unesc(pass);
    if (s->user[0]) { ERR(s, "ALREADY_LOGGED_IN", "This connection is already logged in"); return; }
    if (!is_valid_username(user)) { ERR(s, "NO_SUCH_USER", "No such user"); return; }

    pthread_mutex_lock(&g_store);
    int r = user_lookup(user, NULL, hash, sizeof hash);
    pthread_mutex_unlock(&g_store);
    if (r < 0)  { ERR(s, "STORAGE", "Cannot read user database"); return; }
    if (r == 0) { logmsg(s, "LOGIN failed (no such user) %s", user); ERR(s, "NO_SUCH_USER", "No such user"); return; }
    if (!verify_password(pass, hash)) { logmsg(s, "LOGIN failed (bad password) %s", user); ERR(s, "BAD_PASSWORD", "Incorrect password"); return; }
    if (!session_add(user)) { ERR(s, "ALREADY_LOGGED_IN", "User already has an active session"); return; }
    snprintf(s->user, sizeof s->user, "%.32s", user);
    logmsg(s, "LOGIN ok user=%s", user);
    send_line(&s->c, "OK|LOGIN_SUCCESS|Welcome %s", user);
}

static void cmd_send(session_t *s, char **f)
{
    char to[MAX_LINE], subj[MAX_LINE], body[MAX_LINE];
    snprintf(to, sizeof to, "%s", f[1]);     unesc(to);
    snprintf(subj, sizeof subj, "%s", f[2]); unesc(subj); trim(subj);
    snprintf(body, sizeof body, "%s", f[3]); unesc(body);
    char tmp[MAX_LINE]; snprintf(tmp, sizeof tmp, "%s", body); trim(tmp);

    /* parse recipient list */
    char rcpt[MAX_RCPT][USER_MAX + 1];
    int nr = 0;
    for (char *tok = strtok(to, ","); tok; tok = strtok(NULL, ",")) {
        trim(tok); to_lower(tok);
        if (!*tok) continue;
        if (!is_valid_username(tok)) { char m[128]; snprintf(m, sizeof m, "Invalid recipient: %.40s", tok); ERR(s, "NO_SUCH_USER", m); return; }
        int dup = 0;
        for (int i = 0; i < nr; i++) if (strcmp(rcpt[i], tok) == 0) dup = 1;
        if (dup) continue;
        if (nr == MAX_RCPT) { ERR(s, "TOO_MANY_RECIPIENTS", "At most 10 recipients"); return; }
        snprintf(rcpt[nr++], USER_MAX + 1, "%.32s", tok);
    }
    if (nr == 0)             { ERR(s, "NO_RECIPIENT", "At least one recipient is required"); return; }
    if (!*subj)              { ERR(s, "EMPTY_SUBJECT", "Subject must not be empty"); return; }
    if (!*tmp)               { ERR(s, "EMPTY_BODY", "Message body must not be empty"); return; }
    if (strlen(subj) > SUBJECT_MAX || strlen(body) > BODY_MAX) { ERR(s, "TOO_LONG", "Subject or body too long"); return; }

    char tolist[MAX_RCPT * (USER_MAX + 1) + 1] = "";
    for (int i = 0; i < nr; i++) { if (i) strcat(tolist, ","); strcat(tolist, rcpt[i]); }

    char es[SUBJECT_MAX * 2 + 2], eb[BODY_MAX * 2 + 2], ts[32];
    if (esc(subj, es, sizeof es) || esc(body, eb, sizeof eb)) { ERR(s, "TOO_LONG", "Subject or body too long"); return; }
    now_str(ts, sizeof ts);

    pthread_mutex_lock(&g_store);
    for (int i = 0; i < nr; i++) {                    /* verify all first: all-or-nothing on bad name */
        int r = user_lookup(rcpt[i], NULL, NULL, 0);
        if (r < 0) { pthread_mutex_unlock(&g_store); ERR(s, "STORAGE", "Cannot read user database"); return; }
        if (r == 0) {
            pthread_mutex_unlock(&g_store);
            char m[192]; snprintf(m, sizeof m, "Recipient does not exist: %s", rcpt[i]);
            ERR(s, "NO_SUCH_USER", m); return;
        }
    }
    char *line = malloc(MAX_LINE * 2);
    if (!line) { pthread_mutex_unlock(&g_store); ERR(s, "STORAGE", "Out of memory"); return; }
    char path[600];
    int fail = 0;
    for (int i = 0; i < nr && !fail; i++) {
        path_box(path, sizeof path, rcpt[i], "inbox");
        snprintf(line, MAX_LINE * 2, "%d|%s|%s|%s|%s|U|%s", next_id(path), s->user, tolist, es, ts, eb);
        if (append_line(path, line) != 0) fail = 1;
    }
    if (!fail) {
        path_box(path, sizeof path, s->user, "sent");
        snprintf(line, MAX_LINE * 2, "%d|%s|%s|%s|%s", next_id(path), tolist, es, ts, eb);
        if (append_line(path, line) != 0) fail = 1;
    }
    free(line);
    pthread_mutex_unlock(&g_store);
    if (fail) { ERR(s, "STORAGE", "Could not store message"); return; }
    logmsg(s, "SEND from=%s to=%s", s->user, tolist);
    send_line(&s->c, "OK|SEND_SUCCESS|Delivered to %d recipient(s)", nr);
}

/* INBOX / SENT: "OK|n" followed by n lines of "M|..." or "S|..." */
static void cmd_list(session_t *s, int inbox)
{
    char path[600], line[MAX_LINE * 2];
    path_box(path, sizeof path, s->user, inbox ? "inbox" : "sent");
    char *buf = NULL; size_t sz = 0;
    FILE *m = open_memstream(&buf, &sz);
    if (!m) { ERR(s, "STORAGE", "Out of memory"); return; }
    int n = 0;
    pthread_mutex_lock(&g_store);
    FILE *f = fopen(path, "r");
    if (!f && errno != ENOENT) { pthread_mutex_unlock(&g_store); fclose(m); free(buf); ERR(s, "STORAGE", "Cannot open mailbox"); return; }
    while (f && fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *fl[8];
        if (inbox) {            /* id|from|to|subject|time|status|body */
            if (split_fields(line, fl, 7) != 7) continue;
            fprintf(m, "M|%s|%s|%s|%s|%s\n", fl[0], fl[1], fl[3], fl[4], fl[5]);
        } else {                /* id|to|subject|time|body */
            if (split_fields(line, fl, 5) != 5) continue;
            fprintf(m, "S|%s|%s|%s|%s\n", fl[0], fl[1], fl[2], fl[3]);
        }
        n++;
    }
    if (f) fclose(f);
    pthread_mutex_unlock(&g_store);
    fclose(m);
    send_line(&s->c, "OK|%d", n);
    if (sz) send_all(s->c.fd, buf, sz);
    free(buf);
}

/* READ|id (inbox, marks as read) and READSENT|id */
static void cmd_read(session_t *s, char **f, int inbox)
{
    char *end; long id = strtol(f[1], &end, 10);
    if (*end || id <= 0 || id > 1000000) { ERR(s, "BAD_ID", "Email ID must be a positive number"); return; }
    char path[600], line[MAX_LINE * 2], *fl[8];
    path_box(path, sizeof path, s->user, inbox ? "inbox" : "sent");
    pthread_mutex_lock(&g_store);
    int r = find_record(path, (int)id, inbox ? 7 : 5, line, sizeof line, fl);
    if (r == 1 && inbox && strcmp(fl[5], "U") == 0) {
        char copy[MAX_LINE * 2];
        snprintf(copy, sizeof copy, "%s|%s|%s|%s|%s|%s|%s", fl[0], fl[1], fl[2], fl[3], fl[4], "R", fl[6]);
        if (mark_read(path, (int)id) != 0) logmsg(s, "WARN could not mark read");
        snprintf(line, sizeof line, "%s", copy);
        split_fields(line, fl, 7);
    }
    char *reply = NULL;
    if (r == 1) {
        reply = malloc(MAX_LINE);
        if (reply) {
            if (inbox)  /* OK|id|from|to|subject|time|body */
                snprintf(reply, MAX_LINE, "OK|%s|%s|%s|%s|%s|%s", fl[0], fl[1], fl[2], fl[3], fl[4], fl[6]);
            else        /* sent record is id|to|subject|time|body */
                snprintf(reply, MAX_LINE, "OK|%s|%s|%s|%s|%s|%s", fl[0], s->user, fl[1], fl[2], fl[3], fl[4]);
        }
    }
    pthread_mutex_unlock(&g_store);
    if (r < 0)       ERR(s, "STORAGE", "Cannot open mailbox");
    else if (r == 0) ERR(s, "NO_SUCH_EMAIL", "No email with that ID");
    else if (!reply) ERR(s, "STORAGE", "Out of memory");
    else {
        send_line(&s->c, "%s", reply);
    }
    free(reply);
}

/* returns 0 to close the connection */
static int handle_request(session_t *s, char *line)
{
    char *f[MAX_FIELDS];
    int n = split_fields(line, f, MAX_FIELDS);
    if (n < 0 || !*f[0]) { ERR(s, "MALFORMED", "Malformed request"); return 1; }
    const char *cmd = f[0];
    int logged = s->user[0] != '\0';

    if (!strcmp(cmd, "REGISTER"))      { if (n != 4) ERR(s, "MALFORMED", "Usage: REGISTER|user|email|password"); else cmd_register(s, f); }
    else if (!strcmp(cmd, "LOGIN"))    { if (n != 3) ERR(s, "MALFORMED", "Usage: LOGIN|user|password"); else cmd_login(s, f); }
    else if (!strcmp(cmd, "QUIT"))     { send_line(&s->c, "OK|BYE|Goodbye"); return 0; }
    else if (!strcmp(cmd, "LOGOUT"))   {
        if (!logged) ERR(s, "NOT_LOGGED_IN", "Not logged in");
        else { session_remove(s->user); logmsg(s, "LOGOUT user=%s", s->user); s->user[0] = '\0'; send_line(&s->c, "OK|LOGGED_OUT|Logged out"); }
    }
    else if (!strcmp(cmd, "SEND") || !strcmp(cmd, "INBOX") || !strcmp(cmd, "SENT") ||
             !strcmp(cmd, "READ") || !strcmp(cmd, "READSENT")) {
        if (!logged) { ERR(s, "NOT_LOGGED_IN", "Please log in first"); return 1; }
        if (!strcmp(cmd, "SEND"))       { if (n != 4) ERR(s, "MALFORMED", "Usage: SEND|to|subject|body"); else cmd_send(s, f); }
        else if (!strcmp(cmd, "INBOX")) { if (n != 1) ERR(s, "MALFORMED", "Usage: INBOX"); else cmd_list(s, 1); }
        else if (!strcmp(cmd, "SENT"))  { if (n != 1) ERR(s, "MALFORMED", "Usage: SENT"); else cmd_list(s, 0); }
        else if (!strcmp(cmd, "READ"))  { if (n != 2) ERR(s, "MALFORMED", "Usage: READ|id"); else cmd_read(s, f, 1); }
        else                            { if (n != 2) ERR(s, "MALFORMED", "Usage: READSENT|id"); else cmd_read(s, f, 0); }
    }
    else ERR(s, "INVALID_COMMAND", "Unknown command");
    return 1;
}

/* ---------- per-client thread ---------- */
static void *client_thread(void *arg)
{
    session_t *s = arg;
    struct timeval tv = { IDLE_TIMEOUT, 0 };
    setsockopt(s->c.fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    logmsg(s, "connected");
    send_line(&s->c, "OK|WELCOME|MiniMail 1.0");

    char line[MAX_LINE];
    for (;;) {
        int r = conn_readline(&s->c, line, sizeof line);
        if (r == RL_TOOLONG) { ERR(s, "TOO_LONG", "Request too long"); break; }
        if (r == RL_TIMEOUT) { ERR(s, "TIMEOUT", "Idle timeout"); logmsg(s, "idle timeout"); break; }
        if (r != RL_OK) break;                         /* client vanished */
        if (!handle_request(s, line)) break;
        if (g_stop) break;
    }
    if (s->user[0]) session_remove(s->user);
    close(s->c.fd);
    logmsg(s, "disconnected");
    free(s);
    pthread_mutex_lock(&g_sess); g_nclients--; pthread_mutex_unlock(&g_sess);
    return NULL;
}

static void on_signal(int sig) { (void)sig; g_stop = 1; }

int main(int argc, char **argv)
{
    int port = DEFAULT_PORT, opt;
    const char *bind_ip = "0.0.0.0";
    while ((opt = getopt(argc, argv, "p:d:a:h")) != -1) {
        if (opt == 'p') { char *e; long p = strtol(optarg, &e, 10); if (*e || p < 1 || p > 65535) { fprintf(stderr, "Invalid port: %s\n", optarg); return 1; } port = (int)p; }
        else if (opt == 'd') snprintf(g_datadir, sizeof g_datadir, "%s", optarg);
        else if (opt == 'a') bind_ip = optarg;
        else { fprintf(stderr, "Usage: %s [-p port] [-d datadir] [-a bind_ip]\n", argv[0]); return opt == 'h' ? 0 : 1; }
    }

    char mailroot[600];
    snprintf(mailroot, sizeof mailroot, "%s/mail", g_datadir);
    if ((mkdir(g_datadir, 0700) != 0 && errno != EEXIST) || (mkdir(mailroot, 0700) != 0 && errno != EEXIST)) {
        perror("Cannot create data directory"); return 1;
    }

    struct sigaction sa = { 0 };
    sa.sa_handler = on_signal;                         /* no SA_RESTART: accept() must return on Ctrl-C */
    sigaction(SIGINT, &sa, NULL); sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) { perror("socket"); return 1; }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1) { fprintf(stderr, "Invalid bind address: %s\n", bind_ip); return 1; }
    if (bind(lfd, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); return 1; }
    if (listen(lfd, 16) < 0) { perror("listen"); return 1; }
    logmsg(NULL, "MiniMail server listening on %s:%d, data dir '%s'", bind_ip, port, g_datadir);

    while (!g_stop) {
        struct sockaddr_in ca; socklen_t cl = sizeof ca;
        int cfd = accept(lfd, (struct sockaddr *)&ca, &cl);
        if (cfd < 0) { if (errno == EINTR) continue; perror("accept"); continue; }

        pthread_mutex_lock(&g_sess);
        int busy = g_nclients >= MAX_CLIENTS;
        if (!busy) g_nclients++;
        pthread_mutex_unlock(&g_sess);
        if (busy) { const char *m = "ERR|SERVER_BUSY|Too many clients\n"; send_all(cfd, m, strlen(m)); close(cfd); continue; }

        session_t *s = calloc(1, sizeof *s);
        if (!s) { close(cfd); pthread_mutex_lock(&g_sess); g_nclients--; pthread_mutex_unlock(&g_sess); continue; }
        conn_init(&s->c, cfd);
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ca.sin_addr, ip, sizeof ip);
        snprintf(s->peer, sizeof s->peer, "%s:%d", ip, ntohs(ca.sin_port));

        pthread_t t;
        if (pthread_create(&t, NULL, client_thread, s) != 0) {
            close(cfd); free(s);
            pthread_mutex_lock(&g_sess); g_nclients--; pthread_mutex_unlock(&g_sess);
            continue;
        }
        pthread_detach(t);                             /* nobody joins: resources freed on exit */
    }
    logmsg(NULL, "shutting down");
    close(lfd);
    return 0;
}
