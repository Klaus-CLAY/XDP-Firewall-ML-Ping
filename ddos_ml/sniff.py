import argparse
import pickle
from numpy import NAN
from scapy.all import *
from scapy.layers.inet import *
import pandas as pd
import time
from stage1 import FlowDfGenerator


def sniff_packet_df(sniff_if, sniff_filter='ip', sniff_timeout=1):
    capture = sniff(iface=sniff_if, filter=sniff_filter, timeout=sniff_timeout)

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

        p['Time'] = packet.time - CURR_EPOCH_TIME
        p['Source_ip'] = packet['IP'].src
        p['Destination_IP'] = packet['IP'].dst
        p['Frame_length'] = len(packet['IP'])

        packet_list.append(p)

    return pd.DataFrame(packet_list)[["Time", "Source_ip", 'Source_Port', 'Destination_IP',
                                      'Destination_Port', 'Frame_length']]


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--operate', dest='operate',
                        help='give this flag to analyze flows and block inbound packets if malicious traffic is detected',
                        action='store_true', default=False)
    parser.add_argument('--dump', '-d', dest='dump_traffic',
                        help='give this flag to capture and dump the traffic', action='store_true', default=False)
    parser.add_argument('--dump-output', '-do', dest='dump_output',
                        help='specify a name for output file', default='dump.csv')
    parser.add_argument('--interface', '-if', dest='interface',
                        help='specify an interface to sniff on', default='lo')
    args = parser.parse_args()

    CURR_EPOCH_TIME = int(time.time())
    DDOS_THRESHOLD = 2  # 2 consecutive malicious flows -> Block!
    NORMAL_TRAFFIC = 0
    MAL_TRAFFIC = 1
    with open('dt_model.pkl', 'rb') as f:
        loaded_model = pickle.load(f)
    flow_df_generator = FlowDfGenerator()
    flow_df = pd.DataFrame()
    while True:
        packet_df = sniff_packet_df(args.interface, sniff_timeout=1)
        flow_df = pd.concat([flow_df, flow_df_generator.generate_flow_dataframe(
            packet_df, is_labeled=False)])
        if len(flow_df) > DDOS_THRESHOLD:
            flow_df = flow_df.tail(DDOS_THRESHOLD)
        if args.dump_traffic:
            flow_df.tail(1).to_csv(args.dump_output, mode='a',
                                   index=False, header=not os.path.exists(args.dump_output))

        # print metrics
        for feature in flow_df.iloc[-1]:
            print("{0:.6f}".format(feature), end='\t')
        
        # print traffic type
        x = flow_df[flow_df.columns.difference(['Mean_Time'])]
        predicted_list = list(loaded_model.predict(x))
        traffic_type = MAL_TRAFFIC if (all(predicted_list) and
                                        len(predicted_list) >= DDOS_THRESHOLD) else NORMAL_TRAFFIC
        print(f"--> {predicted_list}, {'Malicious' if traffic_type == MAL_TRAFFIC else 'Normal'}")

        if args.operate:
            if traffic_type == MAL_TRAFFIC:
                print(f'interface \'{args.interface}\' is blocked except for the whitelists!')
                # TODO: edit xdp-firewall's config file