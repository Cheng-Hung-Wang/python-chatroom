#-*- coding:utf-8 -*-

from functools import wraps
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie as cookie
from socketserver import ThreadingMixIn
from queue import Queue

import time
import threading
import json
import uuid

from multiprocessing import Process, Event
from random import randint

message = None

class MessageQueue(Queue):
    pass


class DotDict(dict):
    def __getattribute__(self, name):
        try:
            return self[name]
        except:
            return None


class EventMap(dict):
    def register_event(self, path=None):
        def _register_func(func):
            nonlocal path
            path = func.__name__ if path is None else path
            self[path] = func

            @wraps(func)
            def _event(self, *args, **kwargs):
                return func(self, *args, **kwargs)
            return _event
        return _register_func

def anonymous():
    return '匿名{}'.format(randint(0, 1000))

class Client(object):
    def __init__(self, cid, name=None):
        self.id = cid
        self.name = name or anonymous()
        # self.queue = MessageQueue()

    def __eq__(self, other):
        if isinstance(other, Client):
            return self.id == other.id
        return False

    def __ne__(self, other):
        return (not self.__eq__(other))

    def __repr__(self):
        return "name:{} session_id:{}".format(self.name, self.id)

    def __hash__(self):
        return hash(self.__repr__())


class ChatRequestHandler(BaseHTTPRequestHandler):
    sessioncookies = {}
    # cookie过期时间
    SESSION_MAX_AGE = 3600
    # 连接列表
    CONNECTION_LIST = []
    # 记录用户名称的集合
    USERS = set()
    # 事件函数
    event_map = EventMap()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def find_client(self, sid):
        if not sid:
            return None
        for client in self.CONNECTION_LIST:
            if client.id == sid:
                return client
        return None

    def _write_headers(self, status_code, headers={}):
        self.send_response(status_code)
        headers.setdefault('Content-Type', 'text/html')
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()

    def get_session_id(self):
        cookiestring = "\n".join(self.headers.get_all('Cookie',failobj=[]))
        c = cookie()  
        c.load(cookiestring)

        if 'session_id' in c:
            return c['session_id'].value
        return None

    def _session_cookie(self, forcenew=False):  
        cookiestring = "\n".join(self.headers.get_all('Cookie',failobj=[]))
        c = cookie()  
        c.load(cookiestring)

        try:
            if forcenew or time.time() - int(self.sessioncookies[c['session_id'].value]) > self.SESSION_MAX_AGE:  
                raise ValueError('new cookie needed')  
        except:
            c['session_id'] = uuid.uuid4().hex

        for m in c:  
            if m == 'session_id':
                c[m]["httponly"] = True
                c[m]["max-age"] = self.SESSION_MAX_AGE
                c[m]["expires"] = self.date_time_string(time.time() + self.SESSION_MAX_AGE)
                self.sessioncookies[c[m].value] = time.time()
                self.sessionidmorsel = c[m]
                break
        return c['session_id'].value

    def handle(self):
        super().handle()

    # 在线人数
    @classmethod
    def onlines(self):
        return len(self.CONNECTION_LIST)

    def remove_name(self, name):
        if name in self.USERS:
            self.USERS.remove(name)

    # 请求前获取用户信息
    def get_client(func):
        def _get(self, *args, **kwargs):
            self.session_id = self._session_cookie()
            self.client = self.find_client(self.session_id)
            # print("self.session_id:{}".format(self.session_id))
            # print("self.client:", self.client)
            # print("self.CONNECTION_LIST:", self.CONNECTION_LIST)

            if not self.client:
                client = Client(self.session_id)
                self.client = client
                self.CONNECTION_LIST.append(client)
            return func(self, *args, **kwargs)
        return _get

    def do_POST(self):
        length = int(self.headers['Content-Length'])
        body = self.rfile.read(length)
        path = self.path
        if path.startswith('/'):
            path = path[1:]
        res = self.perform_operation(path, body.decode())
        if res:
            headers = {}
            # json和纯文本
            headers['Content-Type'] = 'text/plain'
            self._write_headers(200, headers)
            try:
                self.wfile.write(res)
            except BrokenPipeError:
                # 客户端断开连接
                pass
        else:
            self._write_headers(404)

    @get_client
    def do_GET(self):
        res = self.get_html(self.path)
        if res:
            headers = {}
            if self.sessionidmorsel is not None:
                headers['Set-Cookie'] = self.sessionidmorsel.OutputString()

            self._write_headers(200, headers)
            self.wfile.write(res.encode())
        else:
            self._write_headers(404)

    @event_map.register_event('post')
    def post(self):
        from html import escape
        name = self.client.name if self.client else '匿名' # 当服务器重启后，client信息会清空
        return message.post({
            'msg': escape(self.body), 
            'user': name
        })

    @event_map.register_event('poll')
    def poll(self):
        msg = message.wait(self.body)
        return msg

    @event_map.register_event('name')
    def change_name(self):
        if self.body and self.body in self.USERS:
            return b''
        name = anonymous()
        if self.client:
            name = self.body if self.body else anonymous()
            self.remove_name(self.client.name)
            self.client.name = name
        self.USERS.add(name)
        print(self.USERS)
        return name.encode()

    @event_map.register_event('exit')
    def exit(self):
        if self.client:
            # 清除用户信息
            self.sessioncookies.pop(self.client.id)
            self.remove_name(self.client.name)
            self.CONNECTION_LIST.remove(self.client)

    def perform_operation(self, oper, body):
        session_id = self.get_session_id()
        self.client = self.find_client(session_id)
        self.body = body

        try:
            return self.event_map[oper].__get__(self)()
            # return self.event_map[oper](DotDict(vars()))
        except KeyError:
            pass
            
    def get_html(self, path):
        # 返回静态模版
        if path in ("/", "/chat", "/index.html"):
            return self.render('chat.html')

    def render(self, template):
        html = ''
        try:
            with open(template, encoding='utf-8') as f:
                html = f.read()
        except:
            pass
        return html


class Message(object):
    def __init__(self):
        self.data = ''
        self.time = 0
        self.user = None
        # 返回json
        self.json_msg = ''
        self.event = threading.Event()
        self.lock = threading.Lock()
        self.event.clear()
        self.max = 20

    def to_json(self):
        return json.dumps({
            'msg': message.data,
            'user': message.user,
            'time': message.time,
            'num': ChatRequestHandler.onlines(),
        }).encode()

    def wait(self, last_mess=''):
        if message.data != last_mess and time.time() - message.time < 60:
            # 重发一分钟内的消息
            return self.json_msg
        self.event.wait()
        self.json_msg = self.to_json()
        return self.json_msg

    def post(self, info):
        with self.lock:
            self.data = info['msg']
            self.user = info['user']
            self.time = time.time()
            self.event.set()
            self.event.clear()
        return b'ok'

class StoppableHTTPServer(HTTPServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stop = False

    def serve_forever(self):
        while not self.stop:
            try:
                self.handle_request()
            except KeyboardInterrupt:
                break


ThreadingMixIn.daemon_threads = True
class ChatHTTPServer(ThreadingMixIn, StoppableHTTPServer):
    pass


def start_server(handler, host, port):
    global message
    message = Message()

    httpd = ChatHTTPServer((host, port), handler)
    httpd.serve_forever()


if __name__ == '__main__':
    start_server(ChatRequestHandler, 'localhost', 8000)
