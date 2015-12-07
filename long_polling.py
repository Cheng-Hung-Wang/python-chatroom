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


class Client(object):
    def __init__(self, cid, name=None):
        self.id = cid
        self.name = name or '匿名'.encode()
        self.queue = MessageQueue()


class ChatRequestHandler(BaseHTTPRequestHandler):
    sessioncookies = {}
    # cookie过期时间
    SESSION_MAX_AGE = 3600
    # 连接列表
    CONNECTION_LIST = []
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

    def do_POST(self):
        length = int(self.headers['Content-Length'])
        body = self.rfile.read(length)
        path = self.path
        if path.startswith('/'):
            path = path[1:]
        res = self.perform_operation(path, body)
        if res:
            headers = {}
            headers['Content-Type'] = 'text/plain'
            self._write_headers(200, headers)
            try:
                self.wfile.write(res)
            except BrokenPipeError:
                # 客户端断开连接
                pass
        else:
            self._write_headers(404)

    def do_GET(self):
        self.session_id = self._session_cookie()
        self.client = self.find_client(self.session_id)
        if not self.client:
            client = Client(self.session_id)
            self.client = client
            self.CONNECTION_LIST.append(client)

        path = self.path

        if path.startswith('/'):
            path = path[1:]

        res = self.get_html(path)
        if res:
            headers = {}
            if self.sessionidmorsel is not None:
                headers['Set-Cookie'] = self.sessionidmorsel.OutputString()

            self._write_headers(200, headers)
            self.wfile.write(res.encode())
        else:
            self._write_headers(404)

    @event_map.register_event('post')
    def post(v):
        name = v.client.name if v.client else '匿名'.encode()
        msg = "{}说: {}".format(name.decode(), v.body.decode()).encode()
        return message.post(msg)

    @event_map.register_event('poll')
    def poll(v):
        msg = message.wait(v.body)
        return msg

    @event_map.register_event('name')
    def change_name(v):
        if v.client:
            v.client.name = v.body
        return bytes("修改成功", 'utf-8')

    @event_map.register_event('exit')
    def exit(v):
        if v.client:
            v.self.CONNECTION_LIST.remove(client)

    def perform_operation(self, oper, body):
        session_id = self.get_session_id()
        client = self.find_client(session_id)

        try:
            return self.event_map[oper](DotDict(vars()))
        except KeyError:
            pass
            
    def get_html(self, path):
        # 返回静态模版
        if path=='' or path=='index.html':
            return self.render('chat.html')

    def render(self, template):
        html = ''
        try:
            with open(template, 'r') as f:
                html = f.read()
        except:
            pass
        return html


class Message(object):
    def __init__(self):
        self.data = ''
        self.time = 0
        self.event = threading.Event()
        self.lock = threading.Lock()
        self.event.clear()

    def wait(self, last_mess=''):
        if message.data != last_mess and time.time() - message.time < 60:
            # resend the previous message if it is within 1 min
            return message.data
        self.event.wait()
        return message.data

    def post(self, data):
        with self.lock:
            self.data = data
            self.time = time.time()
            self.event.set()
            self.event.clear()
        return b'ok'


ThreadingMixIn.daemon_threads = True
class ChatHTTPServer(ThreadingMixIn, HTTPServer):
    pass


def start_server(handler, host, port):
    global message
    message = Message()

    httpd = ChatHTTPServer((host, port), handler)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()


if __name__ == '__main__':
    start_server(ChatRequestHandler, 'localhost', 8000)
