import argparse
import json
import pickle
from numpy import NAN
from scapy.all import *
from scapy.layers.inet import *
import pandas as pd
import time
import re
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
    
    if not len(capture):
        return None

    return pd.DataFrame(packet_list)[["Time", "Source_ip", 'Source_Port', 'Destination_IP',
                                      'Destination_Port', 'Frame_length']]

def xdp_fw_conf_to_json(raw_file_str):
    conf = dict()
    conf['interface'] = re.search(
        r'^interface\s*=\s*\"(.*)\";$', raw_file_str, re.MULTILINE).group(1)
    conf['updatetime'] = re.search(
        r'^updatetime\s*=\s*(.*);$', raw_file_str, re.MULTILINE).group(1)

    begin = raw_file_str.find('(')
    end = raw_file_str.find(')')
    filters_str = raw_file_str[begin+1:end]
    filters_str = re.sub('\s', '', filters_str)
    filters_str = re.sub('=', ':', filters_str)
    filters_str = re.sub(';', ',', filters_str)
    filters_str = re.sub('\(', '[', filters_str)
    filters_str = re.sub('\)', ']', filters_str)
    filters_str = re.sub('([\w.]+)', '"\g<1>"', filters_str)
    filters_str = re.sub('""', '"', filters_str)
    filters_str = f"[{filters_str}]"
    conf['filters'] = json.loads(filters_str)
    return conf

def json_to_xdp_fw_conf(json_cfg):
    fw_conf = ''
    fw_conf += f"interface = \"{json_cfg['interface']}\";\n"
    fw_conf += f"updatetime = {json_cfg['updatetime']};\n"
    fw_conf += "filters = (\n"
    for _filter in json_cfg['filters']:
        fw_conf += "\t{\n"
        count = 0
        for key, val in _filter.items():
            count += 1
            delimiter = '' if count == len(_filter) else ','
            try:
                if val != 'true' and val != 'false':
                    int(val)
                fw_conf += f"\t\t{key} = {val}{delimiter}\n"
            except:
                fw_conf += f"\t\t{key} = \"{val}\"{delimiter}\n"
        fw_conf += "\t}"
        if _filter != json_cfg['filters'][-1]:
            fw_conf += ","
        fw_conf += "\n"
    fw_conf += ");"

    return fw_conf

def change_xdp_fw_config(conf_file_path):
    raw_file_str = ''
    with open(conf_file_path, 'r') as f:
        for line in f:
            raw_file_str += line
    cfg = xdp_fw_conf_to_json(raw_file_str)

    try:
        if cfg['filters'][-1]['enabled'] == 'true' and cfg['filters'][-1]['action'] == '1' and len(cfg['filters'][-1]) == 2:
            cfg['filters'][-1]['action'] = '0'
            print('(level 1 action) blacklist changed to whitelist!')
        else:
            raise Exception
    except:
        cfg['filters'] = [{'enabled': 'true', 'action': '0'}]
        print('(level 2 action) interface blocked completely!')

    xdp_fw_conf = json_to_xdp_fw_conf(cfg)
    with open(conf_file_path, "w") as f:
        f.write(xdp_fw_conf)


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
    parser.add_argument('--conf-path', dest='xdp_fw_conf_path',
                        help='path to xdp firewall config file ', default='xdpfw.conf.example')
    args = parser.parse_args()

    # n consecutive malicious flows -> Block!
    DDOS_THRESHOLD = 2
    # n seconds after changing to whitelist if problem still exists, block the interface
    IF_BLOCK_THRESHOLD = 10
    NORMAL_TRAFFIC = 0
    MAL_TRAFFIC = 1
    CURR_EPOCH_TIME = int(time.time())
    operation_timestamp = 0

    with open('dt_model.pkl', 'rb') as f:
        loaded_model = pickle.load(f)
    flow_df_generator = FlowDfGenerator()
    flow_df = pd.DataFrame()
    while True:
        packet_df = sniff_packet_df(args.interface, sniff_timeout=1)
        if packet_df is None:
            print('No packets received on this interface.')
            continue
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
        print(
            f"--> {predicted_list}, {'Malicious' if traffic_type == MAL_TRAFFIC else 'Normal'}")

        if args.operate and (time.time() - operation_timestamp) > IF_BLOCK_THRESHOLD:
            if traffic_type == MAL_TRAFFIC:
                print(
                    f'attempting to reduce traffic on interface \'{args.interface}\'')
                change_xdp_fw_config(args.xdp_fw_conf_path)
                operation_timestamp = time.time()
