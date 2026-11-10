# MiniMail - Multi-Client Email Service in C

A small educational email system: one TCP **server** (pthread per client) and a text-menu **client**.
Users can register, log in, send mail to one or more users, read their inbox, and view sent mail.

## Files
| File | Purpose |
|---|---|
| `server.c` | Server: sockets, sessions, command handlers, file storage |
| `client.c` | Client: menu UI, request/response handling |
| `common.c / common.h` | Shared: buffered line reader, `send_all`, field escaping, validators |
| `Makefile` | Build + `make test` |
| `tests/test_protocol.py` | 40 automated protocol/concurrency/persistence tests |
| `demo/` | Real transcripts from a 3-client demo run + error cases |

## Build (Linux, gcc, libcrypt)
    make                      # builds ./server and ./client
    # or manually:
    gcc -Wall -Wextra -O2 -pthread server.c common.c -o server -lcrypt
    gcc -Wall -Wextra -O2 client.c common.c -o client

Needs `libcrypt` headers (`sudo apt install libcrypt-dev` on Debian/Ubuntu).

## Run
    ./server                          # port 5000, data in ./data
    ./server -p 6000 -d /tmp/maildata -a 0.0.0.0
    ./client                          # connects to 127.0.0.1:5000
    ./client 192.168.1.20 6000        # server IP/hostname and port

Run at least three clients in three terminals for the demonstration.

## Configuration
| Option | Meaning | Default |
|---|---|---|
| `-p port` | TCP port to listen on | 5000 |
| `-d dir`  | Data directory | `data` |
| `-a ip`   | Address to bind | `0.0.0.0` |

Compile-time limits are in `common.h` (`MAX_LINE`, `SUBJECT_MAX`, `BODY_MAX`, `MAX_RCPT`) and
`server.c` (`MAX_CLIENTS`=100, `IDLE_TIMEOUT`=300 s).

## Data files
    data/users.dat                 username|email|salted SHA-512 crypt hash
    data/mail/<user>/inbox.dat     id|from|to|subject|time|U/R|body
    data/mail/<user>/sent.dat      id|to|subject|time|body
Fields are escaped (`|` -> `\p`, newline -> `\n`, `\` -> `\\`), so each record is exactly one line.

## Example session
    ===== MiniMail =====
    1. Register  2. Login  3. Quit
    ...
    To (comma-separated usernames): bob,carol
    Subject: Internet Technology Lab
    Message (finish with a single '.' on its own line):
    Please complete the socket programming experiment.
    .
      Sent. Delivered to 2 recipient(s)

## Protocol summary (one request line -> one response line, `\n` terminated, `|` separated)
    REGISTER|user|email|pass   -> OK|REGISTERED|msg
    LOGIN|user|pass            -> OK|LOGIN_SUCCESS|msg
    SEND|to1,to2|subject|body  -> OK|SEND_SUCCESS|msg
    INBOX                      -> OK|n   then n lines  M|id|from|subject|time|U/R
    SENT                       -> OK|n   then n lines  S|id|to|subject|time
    READ|id                    -> OK|id|from|to|subject|time|body   (marks read)
    READSENT|id                -> OK|id|from|to|subject|time|body
    LOGOUT / QUIT              -> OK|...
    any failure                -> ERR|CODE|message
Error codes: MALFORMED, INVALID_COMMAND, NOT_LOGGED_IN, ALREADY_LOGGED_IN, BAD_USERNAME, BAD_EMAIL,
BAD_PASSWORD, DUPLICATE_USER, DUPLICATE_EMAIL, NO_SUCH_USER, NO_RECIPIENT, EMPTY_SUBJECT, EMPTY_BODY,
TOO_LONG, TOO_MANY_RECIPIENTS, BAD_ID, NO_SUCH_EMAIL, STORAGE, TIMEOUT, SERVER_BUSY.
Max line 16 KB, subject 100 chars, body 4096 chars, 10 recipients.

## Testing
    make test        # starts its own server on port 5051, runs 40 tests

## Known limitations
- Plain TCP: no TLS, so passwords and mail travel unencrypted. Use only on a trusted network.
- One global storage mutex: simple and correct, but serialises disk access.
- Whole-file scans for lookups (fine for a lab, not for thousands of users).
- No mail deletion, attachments, or password change. A multi-recipient send can be partly delivered if the disk fails midway.
- Login reveals whether a username exists (separate NO_SUCH_USER / BAD_PASSWORD replies, as the assignment requires).
- Mail is stored locally only; not interoperable with SMTP/IMAP.
