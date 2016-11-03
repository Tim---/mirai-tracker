#!/usr/bin/env python3

import sys
import socket
from datetime import datetime
import threading
import time

from attack_parser import parse_atk

class CnCClient(threading.Thread):
    def __init__(self, host, port, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.host, self.port = host, port
        self.buf = b''

    def run_one(self):
        self.s.connect((self.host, self.port))
        sys.stdout.write('# {}:{} connected\n'.format(self.host, self.port))

        # Signature bytes ?
        self.s.sendall(b'\x00\x00\x00\x01')
        # Id field
        id_ = b'telnet.x86'
        self.s.sendall(bytes([len(id_)]) + id_)
        # Initial ping
        self.s.sendall(b'\x00\x00')

        while True:
            try:
                data = self.s.recv(1024)

                if not data:
                    # Connection closed
                    break

                self.buf += data
            except socket.timeout:
                # Send ping every minute if no data received
                self.s.sendall(b'\x00\x00')
                continue

            while len(self.buf) >= 2:
                # We can read size
                size = int.from_bytes(self.buf[:2], byteorder='big')

                if size == 0:
                    # Ping answer
                    self.buf = self.buf[2:]
                elif len(self.buf) >= size:
                    # Attack command, we can read the whole payload
                    payload, self.buf = self.buf[2:size], self.buf[size:]

                    t = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    try:
                        decoded = parse_atk(payload)
                        sys.stdout.write('{} {}:{}: {}\n'.format(t, self.host, self.port, decoded))
                    except Exception as e:
                        sys.stdout.write('{}\n{} {}:{}: {}\n'.format(e, t, self.host, self.port, payload))
                else:
                    # Attack command, not enough bytes
                    break

        self.s.close()

    def run(self):
        while True:
            try:
                self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s.settimeout(60)
                self.run_one()
                sys.stdout.write('# {}:{} got disconnected\n'.format(self.host, self.port))
            except TimeoutError:
                sys.stdout.write('# {}:{} got timeout\n'.format(self.host, self.port))
            except ConnectionRefusedError:
                sys.stdout.write('# {}:{} got refused\n'.format(self.host, self.port))
            time.sleep(60)

class CnCManager(object):
    def __init__(self, servers):
        self.servers = servers

    def run(self):
        threads = []
        for host, port in self.servers:
            t = CnCClient(host, port)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

if __name__ == "__main__":
    # Example C&C servers
    servers = [
        ("www.mufoscam.org", 23),
        ("fuck1.bagthebook.com", 23),
        ("our.bklan.ru", 23),
        ("sdrfafasyy.top", 23),
    ]

    manager = CnCManager(servers)
    manager.run()
