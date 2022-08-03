import argparse
import socket
from time import sleep

if __name__ == '__main__':
    TIME_INTERVAL = 0.2
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', dest='server_ip',
                        help='server IP address', default='127.0.0.1')
    parser.add_argument('--port', dest='server_port',
                        help='server port', default='65432')
    parser.add_argument('--text', '-t', dest='text',
                        help='text to be sent to server', default='Hello World!')
    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((args.server_ip, int(args.server_port)))
        while True:
            try:
                sleep(TIME_INTERVAL)
                s.send(bytes(args.text, 'utf-8'))
                data = s.recv(1024)
                print(f"Received \'{data.decode('utf-8')}\'")
            except:
                print('connection with server terminated')
                break