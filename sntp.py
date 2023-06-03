import socket
import struct
import time
import argparse


def get_current_time():
    """
    Возвращает текущее время в формате, используемом в протоколе SNTP
    """
    ntp_epoch = 2208988800
    current_time = int(time.time()) + ntp_epoch
    return struct.pack('!I', current_time)


def get_response(delay):
    """
    Формирует ответ сервера на запрос клиента
    """
    response = bytearray(48)
    response[0] = 0x1b  # LI, VN, Mode
    response[1] = 0x00  # Stratum
    response[2] = 0x06  # Poll Interval
    response[3] = 0xEC  # Precision
    response[4:8] = b'\x00' * 4  # Root Delay
    response[8:12] = b'\x00' * 4  # Root Dispersion
    response[12:16] = b'\x00' * 4  # Reference Identifier
    response[16:20] = get_current_time()  # Reference Timestamp
    response[20:24] = get_current_time()  # Originate Timestamp
    response[24:28] = get_current_time() + delay  # Receive Timestamp
    response[28:32] = get_current_time() + delay  # Transmit Timestamp
    return response


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--delay', type=int, default=0, help='Delay in seconds')
    parser.add_argument('-p', '--port', type=int, default=1234, help='Port number')
    args = parser.parse_args()

    # Создаем UDP-сокет и привязываем его к заданному порту
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('localhost', args.port))

    print(f'Server started with delay {args.delay} seconds.')

    while True:
        # Ждем запроса от клиента
        data, address = sock.recvfrom(1024)
        #data, address = sock.recvfrom(1234)
        print(f'Client {address[0]} connected.')

        # Формируем и отправляем ответ на запрос клиента
        response = get_response(args.delay)
        sock.sendto(response, address)


if __name__ == '__main__':
    main()
