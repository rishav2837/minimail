/* client.c - MiniMail text-menu client
 * Usage: ./client [server_ip_or_host] [port]      (defaults 127.0.0.1 5000)
 */
#define _GNU_SOURCE
#include "common.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

static conn_t g_conn;
static char   g_user[USER_MAX + 1] = "";

static void die_conn(void)
{
    fprintf(stderr, "\nConnection to server lost.\n");
    close(g_conn.fd);
    exit(1);
}

/* Send one request line and read one response line (stored in resp). */
static void rpc(char *resp, size_t rsz, const char *fmt, ...)
{
    char req[MAX_LINE];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(req, sizeof req - 1, fmt, ap);
    va_end(ap);
    if (n < 0 || n >= (int)sizeof req - 1) { fprintf(stderr, "Request too large.\n"); resp[0] = '\0'; return; }
    req[n++] = '\n';
    if (send_all(g_conn.fd, req, (size_t)n) != 0) die_conn();
    if (conn_readline(&g_conn, resp, rsz) != RL_OK) die_conn();
}

static void quit_client(int code)
{
    char r[MAX_LINE];
    send_all(g_conn.fd, "QUIT\n", 5);
    conn_readline(&g_conn, r, sizeof r);
    close(g_conn.fd);
    printf("Goodbye.\n");
    exit(code);
}

/* Read a line from stdin. EOF => leave cleanly. */
static void ask(const char *label, char *buf, size_t n)
{
    printf("%s", label);
    fflush(stdout);
    if (!fgets(buf, (int)n, stdin)) { printf("\n"); quit_client(0); }
    if (!strchr(buf, '\n')) { int c; while ((c = getchar()) != '\n' && c != EOF) ; }  /* drop overflow */
    buf[strcspn(buf, "\n")] = '\0';
}

static void ask_password(const char *label, char *buf, size_t n)
{
    struct termios o, t;
    int tty = isatty(STDIN_FILENO);
    if (tty) { tcgetattr(STDIN_FILENO, &o); t = o; t.c_lflag &= ~(tcflag_t)ECHO; tcsetattr(STDIN_FILENO, TCSANOW, &t); }
    ask(label, buf, n);
    if (tty) { tcsetattr(STDIN_FILENO, TCSANOW, &o); printf("\n"); }
}

static int is_ok(char **f, int n) { return n > 0 && strcmp(f[0], "OK") == 0; }

static void show_error(char **f, int n)
{
    if (n >= 3) { unesc(f[2]); printf("  Error [%s]: %s\n", f[1], f[2]); }
    else printf("  Error: unexpected server reply.\n");
}

/* Parse a response line in place. Returns field count. */
static int parse(char *resp, char **f, int max)
{
    int n = split_fields(resp, f, max);
    return n < 0 ? 0 : n;
}

static void do_register(void)
{
    char user[128], email[128], pass[128], pass2[128], eu[300], ee[300], ep[300], resp[MAX_LINE], *f[8];
    ask("Username (3-32 letters/digits/_): ", user, sizeof user);
    ask("Email address: ", email, sizeof email);
    ask_password("Password (min 6 chars): ", pass, sizeof pass);
    ask_password("Confirm password: ", pass2, sizeof pass2);
    if (strcmp(pass, pass2) != 0) { printf("  Passwords do not match.\n"); return; }
    if (!is_valid_username(user)) { printf("  Invalid username.\n"); return; }
    if (!is_valid_email(email))   { printf("  Invalid email address.\n"); return; }
    if (esc(user, eu, sizeof eu) || esc(email, ee, sizeof ee) || esc(pass, ep, sizeof ep)) { printf("  Input too long.\n"); return; }
    rpc(resp, sizeof resp, "REGISTER|%s|%s|%s", eu, ee, ep);
    int n = parse(resp, f, 8);
    if (is_ok(f, n)) printf("  Registration successful. You can now log in.\n"); else show_error(f, n);
}

static int do_login(void)
{
    char user[128], pass[128], eu[300], ep[300], resp[MAX_LINE], *f[8];
    ask("Username: ", user, sizeof user);
    ask_password("Password: ", pass, sizeof pass);
    if (esc(user, eu, sizeof eu) || esc(pass, ep, sizeof ep)) { printf("  Input too long.\n"); return 0; }
    rpc(resp, sizeof resp, "LOGIN|%s|%s", eu, ep);
    int n = parse(resp, f, 8);
    if (is_ok(f, n)) {
        snprintf(g_user, sizeof g_user, "%.32s", user);
        to_lower(g_user);
        printf("  Logged in as %s.\n", g_user);
        return 1;
    }
    show_error(f, n);
    return 0;
}

static void do_compose(void)
{
    char to[512], subj[256], line[512], body[BODY_MAX + 2] = "", resp[MAX_LINE], *f[8];
    ask("To (comma-separated usernames): ", to, sizeof to);
    ask("Subject: ", subj, sizeof subj);
    printf("Message (finish with a single '.' on its own line):\n");
    size_t used = 0;
    int too_long = 0;
    for (;;) {
        ask("", line, sizeof line);
        if (strcmp(line, ".") == 0) break;
        size_t l = strlen(line);
        if (used + l + 1 > BODY_MAX) { too_long = 1; continue; }   /* keep reading until '.' */
        memcpy(body + used, line, l); used += l;
        body[used++] = '\n'; body[used] = '\0';
    }
    if (too_long) { printf("  Message exceeds %d characters. Not sent.\n", BODY_MAX); return; }
    if (!*to) { printf("  Recipient is required.\n"); return; }
    if (!*subj) { printf("  Subject must not be empty.\n"); return; }
    if (!*body) { printf("  Message must not be empty.\n"); return; }

    char et[1100], es[600], eb[BODY_MAX * 2 + 2];
    if (esc(to, et, sizeof et) || esc(subj, es, sizeof es) || esc(body, eb, sizeof eb)) { printf("  Input too long.\n"); return; }
    rpc(resp, sizeof resp, "SEND|%s|%s|%s", et, es, eb);
    int n = parse(resp, f, 8);
    if (is_ok(f, n)) { unesc(f[2]); printf("  Sent. %s\n", f[2]); } else show_error(f, n);
}

static void do_list(int inbox)
{
    char resp[MAX_LINE], *f[8];
    rpc(resp, sizeof resp, inbox ? "INBOX" : "SENT");
    int n = parse(resp, f, 8);
    if (!is_ok(f, n) || n < 2) { show_error(f, n); return; }
    int count = atoi(f[1]);
    printf("\n-------- %s --------\n", inbox ? "INBOX" : "SENT MAIL");
    if (inbox) printf("%-5s %-14s %-30s %-20s %s\n", "ID", "FROM", "SUBJECT", "DATE", "STATUS");
    else       printf("%-5s %-24s %-30s %s\n", "ID", "TO", "SUBJECT", "DATE");
    for (int i = 0; i < count; i++) {
        char line[MAX_LINE], *m[8];
        if (conn_readline(&g_conn, line, sizeof line) != RL_OK) die_conn();
        int k = parse(line, m, 8);
        if (inbox && k == 6) {
            unesc(m[3]);
            printf("%-5s %-14.14s %-30.30s %-20s %s\n", m[1], m[2], m[3], m[4], strcmp(m[5], "U") == 0 ? "NEW" : "read");
        } else if (!inbox && k == 5) {
            unesc(m[3]); unesc(m[2]);
            printf("%-5s %-24.24s %-30.30s %s\n", m[1], m[2], m[3], m[4]);
        }
    }
    if (count == 0) printf("(no messages)\n");
    printf("\n");
}

static void do_read(int inbox)
{
    char idbuf[32], resp[MAX_LINE], *f[8];
    ask(inbox ? "Email ID to read: " : "Sent email ID to view: ", idbuf, sizeof idbuf);
    char *end; long id = strtol(idbuf, &end, 10);
    if (*end || id <= 0) { printf("  Please enter a positive number.\n"); return; }
    rpc(resp, sizeof resp, inbox ? "READ|%ld" : "READSENT|%ld", id);
    int n = parse(resp, f, 8);
    if (!is_ok(f, n) || n != 7) { show_error(f, n); return; }
    for (int i = 3; i < 7; i++) if (i != 5) unesc(f[i]);
    unesc(f[6]);
    printf("\n==================== EMAIL #%s ====================\n", f[1]);
    printf("From:    %s\nTo:      %s\nSubject: %s\nDate:    %s\n", f[2], f[3], f[4], f[5]);
    printf("--------------------------------------------------\n%s\n==================================================\n\n", f[6]);
}

int main(int argc, char **argv)
{
    const char *host = argc > 1 ? argv[1] : "127.0.0.1";
    const char *portstr = argc > 2 ? argv[2] : "5000";
    char *e; long port = strtol(portstr, &e, 10);
    if (*e || port < 1 || port > 65535) { fprintf(stderr, "Invalid port: %s\n", portstr); return 1; }

    struct addrinfo hints = { 0 }, *res;
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    int gai = getaddrinfo(host, portstr, &hints, &res);
    if (gai != 0) { fprintf(stderr, "Invalid server address '%s': %s\n", host, gai_strerror(gai)); return 1; }

    int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { perror("socket"); return 1; }
    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        fprintf(stderr, "Cannot connect to %s:%s - is the server running?\n", host, portstr);
        perror("connect"); return 1;
    }
    freeaddrinfo(res);
    conn_init(&g_conn, fd);

    char resp[MAX_LINE], *f[8];
    if (conn_readline(&g_conn, resp, sizeof resp) != RL_OK) die_conn();
    int n = parse(resp, f, 8);
    if (!is_ok(f, n)) { show_error(f, n); close(fd); return 1; }
    printf("Connected to MiniMail server at %s:%s\n", host, portstr);

    for (;;) {
        char choice[16];
        if (!g_user[0]) {
            printf("\n===== MiniMail =====\n1. Register\n2. Login\n3. Quit\n");
            ask("Choice: ", choice, sizeof choice);
            if (choice[0] == '1') do_register();
            else if (choice[0] == '2') do_login();
            else if (choice[0] == '3') quit_client(0);
            else printf("  Invalid choice.\n");
        } else {
            printf("\n===== MiniMail - %s =====\n1. Compose\n2. Inbox\n3. Read email\n4. Sent mail\n5. View sent email\n6. Logout\n", g_user);
            ask("Choice: ", choice, sizeof choice);
            if (choice[0] == '1') do_compose();
            else if (choice[0] == '2') do_list(1);
            else if (choice[0] == '3') do_read(1);
            else if (choice[0] == '4') do_list(0);
            else if (choice[0] == '5') do_read(0);
            else if (choice[0] == '6') {
                rpc(resp, sizeof resp, "LOGOUT");
                g_user[0] = '\0';
                printf("  Logged out.\n");
            } else printf("  Invalid choice.\n");
        }
    }
}
