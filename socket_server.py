#-*- coding:utf-8 -*-
import select
import socket
import sys
import traceback
import types

ADDRESS = ('', 7000)
RECV_BUFFER = 4096

try:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # 当socket关闭时，系统保留端口地址数分钟
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # 绑定地址和端口
    server_socket.bind(ADDRESS)
    # 监听连接
    server_socket.listen(1)
except:
    sys.exit()

# 连接列表
CONNECTION_LIST = [server_socket]

def broadcast_data(sock, message):
    for s in CONNECTION_LIST:
        if s != server_socket and s != sock :
            try :
                if isinstance(message, bytes):
                    s.send(message)
                else:
                    s.send(message.encode())
            except :
                traceback.print_exc()
                s.close()
                CONNECTION_LIST.remove(s)

def close_client_socket(sock):
    clienthost, clientport = sock.getpeername()
    broadcast_data(s, "({}, {}) 已经下线\n".format(clienthost, clientport).encode())
    sys.stdout.write("客户端 ({}, {}) 已经下线\n".format(clienthost, clientport))
    sys.stdout.flush()
    s.close()
    CONNECTION_LIST.remove(s)

while 1:
    try:
        r_sockets, w_sockets, e_sockets = select.select(CONNECTION_LIST, [], [])
    except KeyboardInterrupt:
        sys.exit()
    except:
        traceback.print_exc()

    for s in r_sockets:
        if s == server_socket:
            try:
                clientsock, clientaddr = s.accept()
            except KeyboardInterrupt:
                raise
            except:
                traceback.print_exc()

            # 加入到连接列表
            CONNECTION_LIST.append(clientsock)

            try:
                broadcast_data(clientsock, "[{}:{}] 进入房间\n".format(*clientsock.getpeername()))
                sys.stdout.write("当前聊天室人数：{}\n".format(len(CONNECTION_LIST) - 1))
                sys.stdout.flush()
            except (KeyboardInterrupt, SystemExit):
                raise
            except:
                traceback.print_exc()

        else:
            try:
                data = s.recv(RECV_BUFFER)
                if data:
                    if data == b'<exit>':
                        close_client_socket(s)
                    else:
                        clienthost, clientport = s.getpeername()
                        msg = '< {} :{}> 说：{}'.format(clienthost, clientport, data.decode('utf-8')).encode()
                        broadcast_data(s, msg)
            except:
                traceback.print_exc()
                close_client_socket(s)
                continue

server_socket.close()
