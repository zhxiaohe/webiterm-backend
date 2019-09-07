import io
import logging
import os.path
import socket
import traceback
import uuid
import weakref
import paramiko
import tornado.web
import tornado.websocket
from tornado.ioloop import IOLoop
from tornado.iostream import _ERRNO_CONNRESET
from tornado.options import define, options, parse_command_line
from tornado.util import errno_from_exception
import json
import struct
import time
import datetime



try:
    from json.decoder import JSONDecodeError
except ImportError:
    JSONDecodeError = ValueError

try:
    from types import UnicodeType
except ImportError:
    UnicodeType = str



define('address', default='0.0.0.0', help='listen address')
define('port', default=9008, help='listen port', type=int)


from cryptography.fernet import Fernet





def decrypt_p(password):  ## 解密
    f = Fernet('Ow2Qd11KeZS_ahNOMicpWUr3nu3RjOUYa0_GEuMDlOc=')
    p1 = password.encode()
    token = f.decrypt(p1)
    p2 = token.decode()
    return p2



BUF_SIZE = 32 * 1024
DELAY = 21600
CHANNUM = 4
base_dir = os.path.dirname(__file__)
workers = {}


class UserWorks(object):
    userworks = {}


class SshId(object):
    sshid = {}

SSHID = SshId()

UW = UserWorks()


def recycle(worker):
    if worker.handler:
        return
    logging.debug('Recycling worker {}'.format(worker.id))
    workers.pop(worker.id, None)
    worker.close()


class Worker(object):
    def __init__(self, ssh, chan, dst_addr, username):
        self.loop = IOLoop.current()
        self.ssh = ssh
        self.sshid = str(id(ssh))
        self.chan = chan
        self.dst_addr = dst_addr
        self.fd = chan.fileno()
        self.id = str(id(self))
        self.data_to_dst = []
        self.handler = None
        self.mode = IOLoop.READ
        self.username = username
        self.t = time.time()
        self.ptynum = 1
        self.filename = 'action/{user}_{ssh}_{id}_{t}.cast'.format(user=self.username, ssh=self.sshid, id=self.id,
                                                        t=time.strftime("%Y-%m-%d--%H-%M-%S", time.localtime(self.t)))
        # self.actionplay = ActionLogger(filename=self.filename)

    def __call__(self, fd, events):
        if events & IOLoop.READ:
            self.on_read()
        if events & IOLoop.WRITE:
            self.on_write()
        if events & IOLoop.ERROR:
            self.close()

    def set_handler(self, handler):
        if not self.handler:
            self.handler = handler

    def update_handler(self, mode):
        if self.mode != mode:
            self.loop.update_handler(self.fd, mode)
            self.mode = mode

    def on_read(self):
        logging.debug('worker {} on read'.format(self.id))
        try:
            data = self.chan.recv(BUF_SIZE)
            t = round(time.time() - self.t, 6)
            with open(self.filename, "a") as f:
                f.write(json.dumps([str(t), "o", data.decode()]) + "\n")
                f.close()
        except (OSError, IOError) as e:
            logging.error(e)
            if errno_from_exception(e) in _ERRNO_CONNRESET:
                self.close()
        else:
            logging.debug('"{}" from {}'.format(data, self.dst_addr))
            if not data:
                self.close()
                return

            logging.debug('"{}" to {}'.format(data, self.handler.src_addr))
            try:
                self.handler.write_message(data, binary=True)
            except tornado.websocket.WebSocketClosedError:
                self.close()

    def on_write(self):
        logging.debug('worker {} on write'.format(self.id))
        if not self.data_to_dst:
            return

        data = ''.join(self.data_to_dst)
        logging.debug('"{}" to {}'.format(data, self.dst_addr))

        try:
            # print("send: ", data)
            sent = self.chan.send(data)
        except (OSError, IOError) as e:
            logging.error(e)
            if errno_from_exception(e) in _ERRNO_CONNRESET:
                self.close()
            else:
                self.update_handler(IOLoop.WRITE)
        else:
            self.data_to_dst = []
            data = data[sent:]
            if data:
                self.data_to_dst.append(data)
                self.update_handler(IOLoop.WRITE)
            else:
                self.update_handler(IOLoop.READ)

    def close(self):
        logging.debug('Closing worker {}'.format(self.id))
        if self.handler:
            self.loop.remove_handler(self.fd)
            self.handler.close()
        if self.username in UW.userworks.keys() and self.sshid in UW.userworks[self.username]['sshid'].keys():
            #print("if username:", self.username, UW.userworks.items())
            if self.id in UW.userworks[self.username]["sshid"][self.sshid].keys():
                if len(UW.userworks[self.username]["sshid"][self.sshid]) <= 1 and UW.userworks[self.username]["channum"] == 0:
                    UW.userworks[self.username]["sshid"].pop(self.sshid)
                    self.chan.close()
                    self.ssh.close()
                    logging.info('Connection to {} lost'.format("ssh"))
                else:
                    UW.userworks[self.username]["sshid"][self.sshid].pop(self.id)
                    self.chan.close()
                if not UW.userworks[self.username]["sshid"]:
                    self.ssh.close()
                    logging.info('Connection to {} lost'.format("ssh"))

        else:
            #print("else username:",self.username, UW.userworks.items())
            self.chan.close()
            self.ssh.close()
            logging.info('Connection to {} lost'.format("ssh"))
        logging.info('Connection to {} lost'.format(self.dst_addr))


class IndexHandler(tornado.web.RequestHandler):

    def check_origin(self, origin):
        return True

    def set_default_headers(self):
        self.set_header('Access-Control-Allow-Origin', '*')
        self.set_header('Access-Control-Allow-Headers', '*')
        self.set_header('Access-Control-Max-Age', 1000)
        self.set_header('Content-type', 'application/json')
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.set_header('Access-Control-Allow-Headers',
                        'Content-Type, Access-Control-Allow-Origin, Access-Control-Allow-Headers, X-Requested-By, Access-Control-Allow-Methods')

    def get_privatekey(self):
        try:
            data = self.request.files.get('privatekey')[0]['body']
        except TypeError:
            return
        return data.decode('utf-8')

    def get_specific_pkey(self, pkeycls, privatekey, password):
        logging.info('Trying {}'.format(pkeycls.__name__))
        try:
            pkey = pkeycls.from_private_key(io.StringIO(privatekey),
                                            password=password)
        except paramiko.PasswordRequiredException:
            raise ValueError('Need password to decrypt the private key.')
        except paramiko.SSHException:
            pass
        else:
            return pkey

    def get_pkey(self, privatekey, password):
        password = password.encode('utf-8') if password else None

        pkey = self.get_specific_pkey(paramiko.RSAKey, privatekey, password)\
            or self.get_specific_pkey(paramiko.DSSKey, privatekey, password)\
            or self.get_specific_pkey(paramiko.ECDSAKey, privatekey, password)\
            or self.get_specific_pkey(paramiko.Ed25519Key, privatekey,
                                      password)
        if not pkey:
            raise ValueError('Not a valid private key file or '
                             'wrong password for decrypting the private key.')
        return pkey

    def get_port(self):
        #value = self.get_value('port')
        value = self.body['port']

        try:
            port = int(value)
        except ValueError:
            port = 0

        if 0 < port < 65536:
            return port

        raise ValueError('Invalid port {}'.format(value))

    def get_value(self, name):
        # value = self.get_argument(name)
        value = self.body[name]
        if not value:
            raise ValueError('Empty {}'.format(name))
        return value

    def get_args(self):
        hostname = self.get_value('hostname')
        port = self.get_port()
        username = self.get_value('username')
        password = self.body['password']
        #privatekey = self.get_privatekey()
        # pkey = self.get_pkey(privatekey, password) if privatekey else None
        # print(password)
        # password1 = decrypt_p(password)

        args = (hostname, port, username, password)
        logging.debug(args)
        return args

    def ssh_connect(self, username):
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        args = self.get_args()
        dst_addr = '{}:{}'.format(*args[:2])
        logging.info('Connecting to {}'.format(dst_addr))
        try:
            ssh.connect(*args, timeout=6)
            #SSHID.sshid[id(ssh)] = {'channum': CHANNUM, 'ssh': ssh}
        except socket.error:
            raise ValueError('Unable to connect to {}'.format(dst_addr))
        except paramiko.BadAuthenticationType:
            raise ValueError('Authentication failed.')
        # chan = ssh.invoke_shell(term='xterm')

        worker = self.chan_invoke(ssh, dst_addr, username)
        return worker

    def chan_invoke(self, ssh, dst_addr, username):
        chan = ssh.invoke_shell(term='xterm-color')
        chan.setblocking(0)
        worker = Worker(ssh, chan, dst_addr, username)
        IOLoop.current().call_later(DELAY, recycle, worker)
        return worker

    def post(self):
        worker_id = None
        status = None
        self.body = json.loads(self.request.body)
        username = self.body['username']
        applyquest = self.body['applyquest']
        nowtime = int(time.time())

        if username in UW.userworks.keys() and UW.userworks[username]["channum"] > 0:
            if UW.userworks[username]["timeout"] > nowtime:
                UW.userworks[username]["channum"] -= 1
                worker = self.chan_invoke(UW.userworks[username]["ssh"], UW.userworks[username]["dst_addr"], username)
                workers[worker.id] = worker
                chan_id = {worker.id: worker.id}
                UW.userworks[username].update({"timeout": int(time.time()) + DELAY,
                                               "ssh": worker.ssh, "dst_addr": worker.dst_addr})
                UW.userworks[username]["sshid"].update({worker.sshid: chan_id})
                self.write(dict(id=worker.id, status=status))
            else:
                ssh = UW.userworks[username]["ssh"]
                ssh.close()
                UW.userworks.pop(username)
                self.write(dict(id=[], status="applyquest"))
        else:
            if applyquest != "applyquest":
                self.write(dict(id=[], status="applyquest"))
            else:
                try:
                    worker = self.ssh_connect(username)
                except Exception as e:
                    # logging.error(traceback.format_exc())
                    status = str(e)
                    self.write(dict(id=[], status=status))
                else:
                    workers[worker.id] = worker
                    ssh_id = worker.sshid
                    chan_id = {worker.id: worker.id}
                    if username in UW.userworks.keys():
                        UW.userworks[username]["sshid"].update({ssh_id: chan_id})
                        UW.userworks[username].update({"timeout": int(time.time()) + DELAY, "channum": CHANNUM - 1,
                                                       "ssh": worker.ssh, "dst_addr": worker.dst_addr})
                    else:
                        UW.userworks[username] = {"timeout": int(time.time()) + DELAY, "ssh": worker.ssh,
                                                  "channum": CHANNUM - 1, "dst_addr": worker.dst_addr,
                                                  "sshid": {ssh_id: chan_id}}
                    self.write(dict(id=worker.id, status=status))

    def options(self):
        pass

class WsockHandler(tornado.websocket.WebSocketHandler):

    def __init__(self, *args, **kwargs):
        self.loop = IOLoop.current()
        self.worker_ref = None
        super(self.__class__, self).__init__(*args, **kwargs)

    def set_default_headers(self):
        self.set_header('Access-Control-Allow-Origin', '*')
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.set_header('Access-Control-Max-Age', 1000)
        self.set_header('Access-Control-Allow-Headers', '*')
        self.set_header('Content-type', 'application/json')

    def check_origin(self, origin):
        return True

    def get_addr(self):
        ip = self.request.headers.get_list('X-Real-Ip')
        port = self.request.headers.get_list('X-Real-Port')
        addr = ':'.join(ip + port)
        #if not addr:
        #    addr = '{}:{}'.format(*self.stream.socket.getpeername())
        return addr

    def open(self): #打开了websocket
        self.src_addr = self.get_addr()
        logging.info('Connected from {}'.format(self.src_addr))
        worker = workers.pop(self.get_argument('id'), None)
        if not worker:
            self.close(reason='Invalid worker id')
            return
        self.set_nodelay(True)
        worker.set_handler(self)
        self.worker_ref = weakref.ref(worker)
        self.loop.add_handler(worker.fd, worker, IOLoop.READ)

    def on_message(self, message):  #表示接到浏览器通过websocket传输的字符，这里一次一个字符。
        logging.debug('"{}" from {}'.format(message, self.src_addr))
        ##worker = self.worker_ref()
        ##worker.data_to_dst.append(message)
        ##worker.on_write()

        worker = self.worker_ref()
        try:
            msg = json.loads(message)
        except JSONDecodeError:
            return

        if not isinstance(msg, dict):
            return
        resize = msg.get('resize')
        # print("resize:", resize)
        if resize and len(resize) == 2:
            if worker.ptynum == 1:
                title = {"version": 2, "width": resize[0], "height": resize[1], "timestamp": int(worker.t),
                         "env": {"SHELL": "/bin/bash", "TERM": "xterm-color"}}
                with open(worker.filename, "r+") as f:
                    old = f.read()
                    f.seek(0)
                    f.write(json.dumps(title)+"\n")
                    f.write(old)
                    f.close()
                worker.ptynum += 1
            try:
                worker.chan.resize_pty(*resize)

            except (TypeError, struct.error, paramiko.SSHException):
                pass

        data = msg.get('data')
        if data and isinstance(data, UnicodeType):
            worker.data_to_dst.append(data)
            worker.on_write()

    def on_close(self):#websocket关闭
        logging.info('Disconnected from {}'.format(self.src_addr))
        worker = self.worker_ref() if self.worker_ref else None
        if worker:
            worker.close()
        # self.loop.remove_handler(worker.fd)


class IndexHandlerAction(tornado.web.RequestHandler):

    def check_origin(self, origin):
        return True

    def set_default_headers(self):
        self.set_header('Access-Control-Allow-Origin', '*')
        self.set_header('Access-Control-Allow-Headers', '*')
        self.set_header('Access-Control-Max-Age', 1000)
        self.set_header('Content-type', 'application/json')
        self.set_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.set_header('Access-Control-Allow-Headers',
                        'Content-Type, Access-Control-Allow-Origin, Access-Control-Allow-Headers, X-Requested-By, Access-Control-Allow-Methods')

    def post(self):
        data = []
        for i in os.listdir('action'):
            date = i.split('--')[0].split('_')[-1]
            data.append({'username': i.split('_')[0], 'play': i, 'datetime': date})
        self.write({'data': data})

    def options(self):
        pass

def main():
    settings = {
        'template_path': os.path.join(base_dir, 'templates'),
        'static_path': os.path.join(base_dir, 'static'),
        # 'cookie_secret': uuid.uuid1().hex,
        'xsrf_cookies': False,
        'debug': True
    }

    handlers = [
        (r'/',   IndexHandler),
        (r'/action', IndexHandlerAction),
        (r'/ws', WsockHandler)
    ]

    parse_command_line()
    app = tornado.web.Application(handlers, **settings)
    app.listen(options.port, options.address)
    logging.info('Listening on {}:{}'.format(options.address, options.port))
    IOLoop.current().start()


if __name__ == '__main__':
    main()

