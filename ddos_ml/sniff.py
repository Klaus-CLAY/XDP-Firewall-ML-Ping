from numpy import NAN
from scapy.all import *
from scapy.layers.inet import *
import pandas as pd

# capture = sniff(iface='wlp3s0', filter='ip', count=1000)
capture = sniff(iface='lo', filter='ip', timeout=1)
# print(capture.summary())

packet_list = []
for packet in capture:
    p = dict()
    p['type'] = 'TCP' if TCP in packet else \
        'UDP' if UDP in packet else \
        'IP' if IP in packet else \
        'None'
    if p['type'] == 'None':
        continue
    elif p['type'] == 'TCP':
        p['Source_Port'] = packet['TCP'].sport
        p['Destination_Port'] = packet['TCP'].dport
    elif p['type'] == 'UDP':
        p['Source_Port'] = packet['UDP'].sport
        p['Destination_Port'] = packet['UDP'].dport
    else:
        p['Source_Port'] = NAN
        p['Destination_Port'] = NAN

    p['Time'] = packet.time
    p['Source_ip'] = packet['IP'].src
    p['Destination_IP'] = packet['IP'].dst
    p['Frame_length'] = len(packet['IP'])

    packet_list.append(p)

packet_df = pd.DataFrame(packet_list)[["Time", "Source_ip", 'Source_Port', 'Destination_IP',
                                       'Destination_Port', 'Frame_length']]
print(packet_df)



# print(df)

# print('got 2000 packets')
# for packet in capture:
#     print(packet.summary())
#     # print(packet['IP'].src)
#     # print(packet.time)
#     # print(len(packet['IP']))
#     # print('******************************')

# # wrpcap("packets.pcap", capture)
