# echo-server.py
import argparse
import socket
from threading import Thread


def handle_connection(sock, addr):
    with sock:
        sock.settimeout(4)
        sock.setblocking(1)
        print(f"Connected by {addr}")
        while True:
            data = sock.recv(1024)
            if not data:
                break
            sock.send(data)

    print(f'connection with {addr} terminated')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', dest='server_ip',
                        help='server IP address', default='127.0.0.1')
    parser.add_argument('--port', dest='server_port',
                        help='server port', default='65432')
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((args.server_ip, int(args.server_port)))
        s.listen()
        print(f'server is listenning on {args.server_ip}:{args.server_port}')
        while True:
            sock, addr = s.accept()
            Thread(target=handle_connection, args=(sock, addr)).start()
