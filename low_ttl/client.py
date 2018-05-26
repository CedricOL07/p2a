#!/usr/bin/env python3

import socket as so
from time import sleep

PORT = 7777
HOST = "127.0.0.1"

clt = so.socket(so.AF_INET, so.SOCK_STREAM)
clt.connect((HOST, PORT))

clt.sendall("Hello, this is the client!".encode())
print("[Client] Sent: {}".format("Hello, this is the client!"))
ans = clt.recv(1024)
print("[Client] Received: {}".format(ans.decode()))

sleep(8)

clt.close()
