# sudo apt install python3-scapy
from scapy.all import *
from scapy.layers.inet import *

pkts = sniff(offline="sample.pcap", count=2)
print(pkts)
sendp(pkts, iface="wlp3s0", loop=1, verbose=0)