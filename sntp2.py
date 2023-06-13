import argparse
import datetime
import socket
import struct
from multiprocessing.pool import ThreadPool

START_TIME = datetime.datetime(1900, 1, 1)
LOCAL_HOST = '127.0.0.2'
SNTP_PORT = 1234

pool = ThreadPool(10)


def init_server() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((LOCAL_HOST, SNTP_PORT))
    return s


def generate_time(delta: int) -> bytes:
    return convert_time_to_bytes((datetime.datetime.utcnow() - START_TIME).total_seconds() + delta)


def convert_time_to_bytes(_time):
    second, mili_second = [int(x) for x in str(_time).split('.')]
    return struct.pack('!II', second, mili_second)


def construct_sntp_packet(packet: bytes, received_time: bytes, delta: int) -> bytes:
    first_byte = struct.pack('!B', (0 << 6 | 3 << 3 | 4))
    stratum = struct.pack('!B', 1)
    poll = struct.pack('!b', 0)
    precision = struct.pack('!b', -20)
    delay = struct.pack('!i', 0)
    dispersion = struct.pack('!i', 0)
    serv_id = struct.pack('!i', 0)
    altered_start_time = generate_time(delta)
    input_time = packet[40:48]
    return first_byte + stratum + poll + precision + delay + dispersion + \
           serv_id + altered_start_time + input_time + received_time


def process_query(packet: bytes, delta: int, s: socket.socket, address: str):
    received_time = generate_time(delta)
    response = construct_sntp_packet(packet, received_time, delta)
    s.sendto(response + generate_time(delta), address)


def run_server(delta: int):
    s = init_server()
    while True:
        packet, address = s.recvfrom(1024)
        print(f'{address} accepted')
        pool.apply_async(process_query, args=(packet, delta, s, address))


if __name__ == '__main__':
    try:
        arg_parser = argparse.ArgumentParser()
        arg_parser.add_argument('-d', type=int, default=0, dest='delta')
        arg_values = arg_parser.parse_args()
        run_server(arg_values.delta)
    except KeyboardInterrupt:
        exit(0)
