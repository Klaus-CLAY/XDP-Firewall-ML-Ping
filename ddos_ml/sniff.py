from scapy.all import *
from scapy.layers.inet import *

capture = sniff(iface='lo', filter='ip', count=2000)

print('got 2000 packets')
for packet in capture:
    print(packet.summary())
    print(packet['IP'].src)
    print(packet.time)
    print(len(packet['IP']))
    print('******************************')

wrpcap("packets.pcap", capture)