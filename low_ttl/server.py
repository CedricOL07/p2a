#!/usr/bin/env python3

import socket as so

PORT = 7777
HOST = "127.0.0.1"

srv = so.socket(so.AF_INET, so.SOCK_STREAM)
srv.bind((HOST, PORT))
srv.listen(1)

conn, addr = srv.accept()

data=""
while data!=b"This is an attack, look at my TTL!":
    data = conn.recv(1024)
    print("[Server] Received: {}".format(data))
    if not data: break
    conn.sendall(data.upper())
    print("[Server] Sent: {}".format(data.upper()))

conn.close()
srv.close()
