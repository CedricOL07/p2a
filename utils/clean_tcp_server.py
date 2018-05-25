"""
Very simple TCP server
syntax used is for Python3
"""
import socket

PORT=4446
HOST="127.0.0.1"

srv=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
srv.bind((HOST,PORT))
srv.listen(1)

conn, addr =srv.accept()
while True:
        data=conn.recv(1024)
        if not data: break
        conn.sendall(data.upper())
	
conn.close()
srv.close()
