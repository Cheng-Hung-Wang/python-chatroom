import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.cookies import SimpleCookie as cookie
from socketserver import ThreadingMixIn

import uuid

from queue import Queue

message = None

class Client(object):
    def __init__(self, cid):
        self.id = cid

class ChatRequestHandler(BaseHTTPRequestHandler):
    sessioncookies = {}
    # cookie过期时间
    SESSION_MAX_AGE = 3600

    def _write_headers(self, status_code, headers={}):
        self.send_response(status_code)
        headers.setdefault('Content-Type', 'text/html')
        for name, value in headers.items():
            self.send_header(name, value)
        self.end_headers()

    def _session_cookie(self,forcenew=False):  
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
        self._session_cookie()

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

    def perform_operation(self, oper, body):
        if oper == 'poll':
            return message.wait(body)
        elif oper == 'post':
            print("{}:{} 发言".format(*self.client_address))
            return message.post(body)
        elif oper == 'exit':
            pass

    def get_html(self, path):
        if path=='' or path=='index.html':
            return '''
            <body>
            <style>
            iframe {
                width: 400px;
                height: 600px;
            }
            </style>
            <iframe src="room.html"></iframe>
            <iframe src="room.html"></iframe>
            <iframe src="room.html"></iframe>
            </body>
            '''
        elif path=='room.html':
            return '''
            <body>
            <script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.4/jquery.min.js"></script>
            <input id="input"/>
            <button id="post">post</button>
            <script>
            $('#post').click(function(){
                $.ajax('/post', {
                    method: 'POST',
                    timeout: 1000,
                    data: $('#input').val()
                });
            });

            $(window).bind("beforeunload", function() { 
                $.ajax('/exit', {
                    method: 'POST',
                });
            });

            var last_message = '';
            (function poll() {
                $.ajax('/poll', {
                    method: 'POST',
                    timeout: 1000*60*10, //10 minutes
                    success: function(data){
                        $("<p>"+data+"</p>").appendTo($(document.body));
                        last_message = data;
                        poll();
                    },
                    error: function(){
                        setTimeout(poll, 1000);
                    },
                    data: last_message
                });
            }());
            </script>
            </body>
            '''


class Message(object):
    def __init__(self):
        self.data = ''
        self.time = 0
        self.event = threading.Event()
        self.lock = threading.Lock()
        self.event.clear()

    def wait(self, last_mess=''):
        if message.data != last_mess and time.time()-message.time < 60:
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
