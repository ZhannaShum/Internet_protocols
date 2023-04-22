import argparse
import socket
import threading


def scan_tcp_ports(host, start_port, end_port, result_list):
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, 'tcp')
            except:
                service = ''
            open_ports.append((port, 'TCP', service))
        sock.close()
    result_list.extend(open_ports)


def scan_udp_ports(host, start_port, end_port, result_list):
    open_ports = []
    for port in range(start_port, end_port + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, 'udp')
                if service:
                    open_ports.append((port, 'UDP', service))
            except:
                pass
        sock.close()
    result_list.extend(open_ports)


# На вход в терминал подается: адрес хоста, -t и/или -u (tcp и/или udp соответственно),
# а также -p и диапазон портов через пробел
# Пример ввода: python localhost -t -u -p 1 100

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Scan TCP and UDP ports of a remote computer.')
    parser.add_argument('host', metavar='HOST', type=str,
                        help='IP address or hostname of the remote computer')
    parser.add_argument('-t', '--tcp', action='store_true',
                        help='scan TCP ports')
    parser.add_argument('-u', '--udp', action='store_true',
                        help='scan UDP ports')
    parser.add_argument('-p', '--ports', metavar='N1 N2', type=int, nargs=2,
                        help='port range to scan (default: 1-65535)',
                        default=[1, 65535])
    args = parser.parse_args()

    if not args.tcp and not args.udp:
        print('Error: at least one of -t and -u must be specified.')
        exit()

    try:
        ip = socket.gethostbyname(args.host)
    except:
        print('Error: could not resolve hostname.')
        exit()

    tcp_threads = []
    udp_threads = []

    if args.tcp:
        print('Scanning TCP ports...')
        tcp_ports = []
        for i in range(args.ports[0], args.ports[1] + 1, 100):
            t = threading.Thread(target=scan_tcp_ports, args=(
            ip, i, min(i + 99, args.ports[1]), tcp_ports))
            tcp_threads.append(t)
            t.start()

        for t in tcp_threads:
            t.join()

        print('Open TCP ports:')
        for port in sorted(tcp_ports):
            if port[2]:
                print(f'TCP {port[0]} {port[2]}')
            else:
                print(f'TCP {port[0]}')

    if args.udp:
        print('Scanning UDP ports...')
        udp_ports = []
        for i in range(args.ports[0], args.ports[1] + 1, 100):
            t = threading.Thread(target=scan_udp_ports, args=(
            ip, i, min(i + 99, args.ports[1]), udp_ports))
            udp_threads.append(t)
            t.start()

        for t in udp_threads:
            t.join()

        print('Open UDP ports:')
        for port in sorted(udp_ports):
            if port[2]:
                print(f'UDP {port[0]} {port[2]}')
            else:
                print(f'UDP {port[0]}')
