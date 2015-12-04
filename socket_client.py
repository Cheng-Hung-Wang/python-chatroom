#-*- coding:utf-8 -*-
import select
import socket
import sys

ADDRESS = ('', 7000)

RECV_BUFFER = 4096

try:
	client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client_socket.connect(ADDRESS)
except:
	sys.exit()

while 1:
	try:
		rlist = [sys.stdin, client_socket]
		r_sockets, w_sockets, e_sockets = select.select(rlist , [], [])
		for s in r_sockets:
			if s == client_socket:
				data = s.recv(RECV_BUFFER)
				if not data:
					sys.stdout.write("与服务器断开连接\n")
					raise
				else:
					sys.stdout.write(data.decode())
					sys.stdout.flush()
			else:
				msg = sys.stdin.readline()
				sys.stdout.writelines('<你> 说：{}'.format(msg))
				client_socket.send(msg.encode())
				sys.stdout.flush()
	except KeyboardInterrupt:
		client_socket.send(b'<exit>')
	except:
		client_socket.close()
		sys.exit()
