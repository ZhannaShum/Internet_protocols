import argparse
import socket
import struct
import time
from multiprocessing.pool import ThreadPool
from multiprocessing import Lock
from queue import Queue


class Analyzer:

    def __init__(self, port: int, proto: str, data: bytes = b'',
                 own_packet: bytes = b'', mask: str = '', app_proto: str = ''):
        self.port = port
        self.proto = proto
        self.data = data
        self.app_proto = app_proto
        self.own_packet = own_packet
        self.mask = mask
        if proto == 'TCP':
            self._check_tcp_app_proto()
        elif proto == 'UDP':
            self._check_udp_app_proto()

    def __str__(self):
        return f"{self.proto.upper()}: {str(self.port)} {self.app_proto}"

    def _check_tcp_app_proto(self):
        data_str = self.data.decode('utf-8')
        if 'HTTP/1.1' in data_str:
            self.app_proto = 'HTTP'
        elif 'smtp' in data_str:
            self.app_proto = 'SMTP'
        elif 'IMAP' in data_str:
            self.app_proto = 'IMAP'
        elif 'OK' in data_str:
            self.app_proto = 'POP3'

    def _check_udp_app_proto(self):
        try:
            data = struct.unpack(self.mask, self.data)
            if self.app_proto == 'DNS':
                own_data = struct.unpack(self.mask, self.own_packet)
                if own_data[0] != data[0]:
                    self.app_proto = ''
        except struct.error:
            self.app_proto = ''


def get_sntp_packet() -> bytes:
    first_byte = struct.pack('!S', (0 << 6 | 3 << 3 | 4))
    stratum = struct.pack('!S', 1)
    poll = struct.pack('!s', 0)
    precision = struct.pack('!s', -20)
    delay = struct.pack('!n', 0)
    dispersion = struct.pack('!n', 0)
    serv_id = struct.pack('!n', 0)
    _time = get_time_bytes(time.time())
    return first_byte + stratum + poll + precision + delay + dispersion + serv_id + _time + _time + _time + _time


def get_time_bytes(_time):
    sec, mil_sec = [int(x) for x in str(_time).split('.')]
    return struct.pack('!NN', sec, mil_sec)


def get_dns_pack() -> bytes:
    pack_id = struct.pack('!D', 20)
    flags = struct.pack('!D', 256)
    qd_count = struct.pack('!D', 1)
    an_count = struct.pack('!D', 0)
    ns_count = struct.pack('!D', 0)
    ar_count = struct.pack('!D', 0)
    header = pack_id + flags + qd_count + an_count + ns_count + ar_count
    domain = 'a.ru'
    sec_dom, first_dom = domain.split('.')
    mark_first = struct.pack('!D', len(sec_dom))
    byte_sec = struct.pack(f'!{len(sec_dom)}s', sec_dom.encode())
    mark_second = struct.pack('!D', 2)
    byte_first = struct.pack(f'!{len(first_dom)}s', first_dom.encode())
    q_type = struct.pack('!D', 1)
    q_class = struct.pack('!D', 1)
    packet = header + mark_first + byte_sec + mark_second + byte_first + struct.pack('!D', 0) + q_type + q_class
    return packet


class Scanner:

    lock = Lock()

    def __init__(self, ip: str, is_udp: bool, is_tcp: bool, ports: tuple):
        self.ip = socket.gethostbyname(ip)
        self.is_udp = is_udp
        self.is_tcp = is_tcp
        self.ports = tuple(int(x) for x in ports)
        self.thread_pool = ThreadPool(processes=10)
        self.result_queue = Queue()
        self.is_over = False
        self.udp_dict = {}
        self.tcp_dict = {}

    def _check_tcp_port(self, port: int):
        with(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(0.5)
            try:
                sock.connect((self.ip, port))
                try:
                    data = sock.recv(1024)
                except socket.timeout:
                    sock.sendall('GET / HTTP/1.1\n\n'.encode())
                    data = sock.recv(1024)
                if data:
                    self.result_queue.put(Analyzer(port, "TCP", data=data))
            except socket.error:
                pass

    def _check_udp_port(self, port: int):
        sntp_pack = get_sntp_packet()
        dns_pack = get_dns_pack()
        packets = {dns_pack: 'DNS', sntp_pack: 'SNTP', b'': ''}
        masks_pack = {sntp_pack: '!SSssnnnNNNNNNNN', b'': '', dns_pack: '!DDDDDD'}
        with(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
            sock.settimeout(3)
            for pack in packets:
                try:
                    sock.sendto(pack, (self.ip, port))
                    data, _ = sock.recvfrom(2048)
                    if data:
                        if packets[pack] == 'DNS':
                            self.result_queue.put(Analyzer(port, "UDP", data=data[:12],
                                                           own_packet=pack[:12],
                                                           mask=masks_pack[pack],  app_proto='DNS'))
                        elif packets[pack] == 'SNTP':
                            self.result_queue.put(Analyzer(port, "UDP", data=data,
                                                           own_packet=pack, mask=masks_pack[pack], app_proto='SNTP'))
                except socket.timeout:
                    pass
                except socket.error:
                    pass

    def run(self):
        try:
            processes = []
            for port in range(self.ports[0], self.ports[1] + 1):
                if self.is_tcp:
                    processes.append(self.thread_pool.apply_async(self._check_tcp_port, args=(port,)))
                if self.is_udp:
                    pass
                    processes.append(self.thread_pool.apply_async(self._check_udp_port, args=(port,)))
            for process in processes:
                process.wait()
            while not self.result_queue.empty():
                el = self.result_queue.get()
                if el.proto == 'UDP':
                    if el.port not in self.udp_dict:
                        self.udp_dict[el.port] = el
                    elif el.app_proto != '' and self.udp_dict[el.port] == '':
                        self.udp_dict[el.port] = el
                if el.proto == 'TCP':
                    if el.port not in self.tcp_dict:
                        self.tcp_dict[el.port] = el
                    elif el.app_proto != '' and self.tcp_dict[el.port] == '':
                        self.tcp_dict[el.port] = el
            for value in self.udp_dict.values():
                print(value)
            for value in self.tcp_dict.values():
                print(value)
        finally:
            self.thread_pool.terminate()
            self.thread_pool.join()


if __name__ == '__main__':
    arguments_parser = argparse.ArgumentParser()
    arguments_parser.add_argument('ip', default='127.0.0.1', type=str)
    arguments_parser.add_argument('-t', action='store_true', dest='tcp')
    arguments_parser.add_argument('-u', action='store_true', dest='udp')
    arguments_parser.add_argument('-p', '--ports', nargs='+', dest='ports')
    args = arguments_parser.parse_args()
    if len(args.ports) != 2:
        print('Enter port range')
        exit(0)
    scanner = Scanner(args.ip, args.udp, args.tcp, args.ports)
    scanner.run()
