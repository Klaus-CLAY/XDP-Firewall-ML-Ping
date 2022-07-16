from scapy.all import *
from scapy.layers.inet import *
# from scapy.utils import *

# pkts = Raw(import_hexcap())
pkts = sniff(offline="sample.pcap", count=2)
print(pkts)

# target_ip = "192.168.1.1"
# target_port = 80

# ip = IP(src=RandIP("192.168.1.1/24"), dst=target_ip)
# tcp = TCP(sport=RandShort(), dport=target_port, flags="S")
# raw = Raw(b"X"*1024)

# p = ip / tcp / raw
sendp(pkts, iface="wlp3s0", loop=1, verbose=0)



# # packet = Dot11(bytearray.fromhex(hexdump))