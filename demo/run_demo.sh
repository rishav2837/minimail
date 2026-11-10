#!/bin/bash
# Three simultaneous client sessions against a server on port 5060
cd "$(dirname "$0")/.."
( printf '1\nalice\nalice@iitlab.local\nsecret1\nsecret1\n2\nalice\nsecret1\n'; sleep 2; printf '1\nbob,carol\nInternet Technology Lab\nPlease complete the socket programming experiment.\nSubmit by Friday.\n.\n'; sleep 3; printf '4\n5\n1\n6\n3\n' ) | timeout 30 ./client 127.0.0.1 5060 > demo/client_alice.txt 2>&1 &
( printf '1\nbob\nbob@iitlab.local\nsecret2\nsecret2\n2\nbob\nsecret2\n'; sleep 6; printf '2\n3\n1\n2\n1\ncarol\nRe: Internet Technology Lab\nWill do, thanks!\n.\n6\n3\n' ) | timeout 30 ./client 127.0.0.1 5060 > demo/client_bob.txt 2>&1 &
( printf '1\ncarol\ncarol@iitlab.local\nsecret3\nsecret3\n2\ncarol\nwrongpw\n2\ncarol\nsecret3\n'; sleep 7; printf '2\n3\n1\n3\n99\n6\n3\n' ) | timeout 30 ./client 127.0.0.1 5060 > demo/client_carol.txt 2>&1 &
wait
