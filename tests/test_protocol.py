#!/usr/bin/env python3
"""MiniMail protocol/regression tests. Starts a fresh server on a test port and
talks raw protocol over TCP. Run from the project directory: python3 tests/test_protocol.py"""
import os, shutil, socket, subprocess, sys, threading, time

PORT, DATA = 5051, "testdata"
results = []

def start_server():
    return subprocess.Popen([os.environ.get("SERVER", "./server"), "-p", str(PORT), "-d", DATA],
                            stderr=open(DATA + ".log", "a"))

class C:
    def __init__(self):
        self.s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
        self.f = self.s.makefile("rb")
        self.greet = self.line()
    def line(self):
        return self.f.readline().decode().rstrip("\n")
    def req(self, text):
        self.s.sendall((text + "\n").encode())
        return self.line()
    def close(self):
        self.s.close()

def check(name, cond, detail=""):
    results.append(cond)
    print(("PASS" if cond else "FAIL"), "-", name, ("" if cond else "  -> " + detail))

def code(r):  # error code of an ERR reply
    p = r.split("|")
    return p[1] if p[0] == "ERR" and len(p) > 1 else r

def main():
    shutil.rmtree(DATA, ignore_errors=True); os.makedirs(DATA)
    srv = start_server(); time.sleep(0.5)
    try:
        a = C(); check("T01 server greets new client", a.greet.startswith("OK|WELCOME"), a.greet)
        check("T02 register alice", a.req("REGISTER|alice|alice@iitlab.local|secret1").startswith("OK|REGISTERED"))
        check("T03 duplicate username rejected", code(a.req("REGISTER|alice|other@iitlab.local|secret1")) == "DUPLICATE_USER")
        check("T04 duplicate email rejected", code(a.req("REGISTER|alice2|alice@iitlab.local|secret1")) == "DUPLICATE_EMAIL")
        check("T05 invalid email rejected", code(a.req("REGISTER|bob|not-an-email|secret1")) == "BAD_EMAIL")
        check("T06 short password rejected", code(a.req("REGISTER|bob|bob@iitlab.local|abc")) == "BAD_PASSWORD")
        check("T07 path-traversal username rejected", code(a.req("REGISTER|../evil|e@iitlab.local|secret1")) == "BAD_USERNAME")
        check("T08 register bob and carol", a.req("REGISTER|bob|bob@iitlab.local|secret2").startswith("OK") and
              a.req("REGISTER|carol|carol@iitlab.local|secret3").startswith("OK"))
        users = open(DATA + "/users.dat").read()
        check("T09 passwords stored hashed, not plaintext", "secret1" not in users and "$6$" in users)

        check("T10 login with wrong password", code(a.req("LOGIN|alice|wrongpw")) == "BAD_PASSWORD")
        check("T11 login non-existent user", code(a.req("LOGIN|nobody|secret1")) == "NO_SUCH_USER")
        check("T12 commands need login", code(a.req("INBOX")) == "NOT_LOGGED_IN")
        check("T13 login alice ok", a.req("LOGIN|alice|secret1").startswith("OK|LOGIN_SUCCESS"))
        b = C()
        check("T14 second session for same user rejected", code(b.req("LOGIN|alice|secret1")) == "ALREADY_LOGGED_IN")
        check("T15 login bob ok (second client)", b.req("LOGIN|bob|secret2").startswith("OK"))

        check("T16 send to non-existent user", code(a.req("SEND|ghost|Hi|Hello")) == "NO_SUCH_USER")
        check("T17 empty subject", code(a.req("SEND|bob||Hello")) == "EMPTY_SUBJECT")
        check("T18 empty body", code(a.req("SEND|bob|Hi|")) == "EMPTY_BODY")
        check("T19 no recipient", code(a.req("SEND||Hi|Hello")) == "NO_RECIPIENT")
        check("T20 send to bob", a.req("SEND|bob|Internet Technology Lab|Please complete the socket experiment.").startswith("OK|SEND_SUCCESS"))
        check("T21 send to two recipients", a.req("SEND|bob,carol|Meeting|Tomorrow 10am").startswith("OK|SEND_SUCCESS|Delivered to 2"))

        r = b.req("INBOX"); rows = [b.line() for _ in range(int(r.split("|")[1]))]
        check("T22 bob inbox has 2 unread mails", r == "OK|2" and all(x.endswith("|U") for x in rows), r + str(rows))
        r = b.req("READ|1")
        check("T23 read mail shows sender/subject/body", r.startswith("OK|1|alice|bob|Internet Technology Lab|") and r.endswith("Please complete the socket experiment."), r)
        r = b.req("INBOX"); rows = [b.line() for _ in range(2)]
        check("T24 mail marked read after reading", rows[0].endswith("|R") and rows[1].endswith("|U"), str(rows))
        check("T25 read non-existent id", code(b.req("READ|99")) == "NO_SUCH_EMAIL")
        check("T26 read bad id", code(b.req("READ|abc")) == "BAD_ID")

        r = a.req("SENT"); rows = [a.line() for _ in range(int(r.split("|")[1]))]
        check("T27 sent list shows 2 mails", r == "OK|2" and rows[0].startswith("S|1|bob|Internet Technology Lab") and rows[1].startswith("S|2|bob,carol|Meeting"), r + str(rows))
        r = a.req("READSENT|2")
        check("T28 view sent mail", r.startswith("OK|2|alice|bob,carol|Meeting|") and r.endswith("Tomorrow 10am"), r)

        # special characters: '|' => \p, newline => \n, backslash => \\
        check("T29 special chars round-trip", a.req(r"SEND|carol|A \p B|line1\nline2 \\ end \p").startswith("OK"))
        c = C(); c.req("LOGIN|carol|secret3")
        r = c.req("INBOX"); rows = [c.line() for _ in range(int(r.split("|")[1]))]
        r = c.req("READ|2")
        check("T30 escaped body stored/returned intact", r.endswith(r"line1\nline2 \\ end \p") and r"A \p B" in r, r)

        check("T31 invalid command", code(a.req("FLY|away")) == "INVALID_COMMAND")
        check("T32 malformed request (wrong field count)", code(a.req("LOGIN|onlyone")) == "MALFORMED")
        check("T33 empty request", code(a.req("")) == "MALFORMED")
        check("T34 lowercase command rejected (case-sensitive)", code(a.req("inbox")) == "INVALID_COMMAND")

        e = C(); e.s.sendall(b"X" * 20000)
        r = e.line()
        check("T35 oversized request rejected, connection closed", code(r) == "TOO_LONG", r)
        e.close()
        d = C(); d.s.sendall(b"REGISTER|abrupt|abrupt@iitlab.local|sec"); d.close()   # half a request then vanish
        time.sleep(0.3)
        check("T36 server alive after abrupt disconnect", srv.poll() is None and C().greet.startswith("OK"))

        check("T37 logout then re-login allowed", a.req("LOGOUT").startswith("OK") and a.req("LOGIN|alice|secret1").startswith("OK"))
        a.req("QUIT"); b.req("QUIT"); c.req("QUIT")

        # persistence across a server restart
        srv.terminate(); srv.wait(); srv = start_server(); time.sleep(0.5)
        p = C(); p.req("LOGIN|bob|secret2"); r = p.req("INBOX")
        check("T38 data persists after server restart", r == "OK|2", r)
        p.req("QUIT")

        # concurrency: 6 clients log in at once, each sends 10 mails to every other client
        names = ["user%d" % i for i in range(6)]
        boot = C()
        for n in names: boot.req("REGISTER|%s|%s@iitlab.local|password" % (n, n))
        boot.req("QUIT")
        errors = []
        def worker(me):
            try:
                w = C()
                assert w.req("LOGIN|%s|password" % me).startswith("OK")
                for k in range(10):
                    for other in names:
                        if other != me:
                            r = w.req("SEND|%s|from %s #%d|body %d" % (other, me, k, k))
                            if not r.startswith("OK"): errors.append(r)
                w.req("QUIT")
            except Exception as ex:
                errors.append(repr(ex))
        th = [threading.Thread(target=worker, args=(n,)) for n in names]
        [t.start() for t in th]; [t.join() for t in th]
        check("T39 6 concurrent clients, 300 mails sent without error", not errors, str(errors[:3]))
        ok = True
        for n in names:
            w = C(); w.req("LOGIN|%s|password" % n)
            r = w.req("INBOX"); rows = [w.line() for _ in range(int(r.split("|")[1]))]
            ids = [x.split("|")[1] for x in rows]
            if len(rows) != 50 or len(set(ids)) != 50: ok = False; print("   ", n, len(rows), len(set(ids)))
            w.req("QUIT")
        check("T40 each inbox has exactly 50 mails with unique IDs (no lost updates)", ok)
    finally:
        srv.terminate(); srv.wait()
    passed = sum(results)
    print("\n%d/%d tests passed" % (passed, len(results)))
    sys.exit(0 if passed == len(results) else 1)

main()
