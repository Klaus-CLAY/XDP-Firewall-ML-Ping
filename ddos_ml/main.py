import matplotlib.pyplot as plt
import pandas as pd
# from sklearn.model_selection import train_test_split
# from sklearn.model_selection import cross_val_score
# from sklearn.model_selection import StratifiedKFold
# from sklearn.metrics import classification_report
# from sklearn.metrics import confusion_matrix
# from sklearn.metrics import accuracy_score
# from sklearn.tree import DecisionTreeClassifier
# from sklearn.neighbors import KNeighborsClassifier
# from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
import numpy as np
# import seaborn as sns
# time, frame_number, frame_length, src_ip, dst_ip, src_port, dst_port, syn, ack, rst, ttl, tcp_protocol

class Stage1:
    def __init__(self, victim_ip):
        self.VICTIM_IP = victim_ip
        self.BENIGN_TRAFFIC = 0
        self.MALICOUS_TRAFFIC = 1
        self.attack_intervals = None

    def do_preprocessings(self, dataset_path, begin=0, end=-1):
        df = pd.read_csv(dataset_path)[begin:end]
        df['Traffic_Type'] = self.BENIGN_TRAFFIC
        df.loc[df['Destination_IP'] == self.VICTIM_IP, 'Traffic_Type'] = self.MALICOUS_TRAFFIC
        df = df[["Time", "Source_ip", 'Source_Port', 'Destination_IP',
                'Destination_Port', 'Frame_length', "Traffic_Type"]]

        mal_packet_count = len(df[df['Traffic_Type'] == self.MALICOUS_TRAFFIC])
        print(f'malicious records count: {mal_packet_count} / {len(df)}')

        self.attack_intervals = self.__get_attack_intervals(df)
        print(f'attack intervals: {self.attack_intervals}')
        
        return df

    def generate_flow_dataframe(self, df, chunk_size=10000):
        flow_list = []
        for i in range(len(df)//chunk_size):
            flow_list.append(self.__process_packet_flows(df[chunk_size*i:chunk_size*(i+1)], self.attack_intervals))

        return pd.DataFrame(flow_list)

    def __process_packet_flows(self, df, attack_intervals):
        log_row = dict()
        time_interval = df['Time'].max() - df['Time'].min()
        # mean_time = df['Time'].mean()
        # print(f'mean time: {mean_time}')

        unique_src_ip_count = len(df['Source_ip'].unique())
        unique_src_port_count = len(df['Source_Port'].unique())

        log_row['Mean_Time'] = df['Time'].mean()
        log_row['SSIP'] = unique_src_ip_count / time_interval
        log_row['SSP'] = unique_src_port_count / time_interval
        # log_row['SDFP']
        log_row['SDFB'] = df['Frame_length'].std()
        log_row['SFE'] = len(df) / time_interval
        log_row['RPF'] = self.__calc_pair_flow_ratio(df)
        log_row['Traffic_Type'] = self.BENIGN_TRAFFIC
        for interval in attack_intervals:
            if log_row['Mean_Time'] >= interval[0] and log_row['Mean_Time'] <= interval[1]:
                log_row['Traffic_Type'] = self.MALICOUS_TRAFFIC
        
        return log_row

    def __get_attack_intervals(self, df):
        threshold = 10
        attack_intervals = []
        times_list = df.loc[df['Traffic_Type'] == self.MALICOUS_TRAFFIC, 'Time']
        begin = times_list.iloc[0]
        end = times_list.iloc[0]
        for t in times_list:
            delta = t - end
            if t == times_list.iloc[len(times_list)-1]:
                attack_intervals.append((begin, end))
                break

            if delta <= threshold:
                end = t
            else:
                attack_intervals.append((begin, end))
                begin = t
                end = t

        return attack_intervals

    def __calc_pair_flow_ratio(self, df):
        inbound_socks = set(df.groupby(['Source_ip', 'Source_Port']).count().index)
        outbound_socks = set(df.groupby(
            ['Destination_IP', 'Destination_Port']).count().index)

        return len(inbound_socks & outbound_socks) / len(inbound_socks)



stage1 = Stage1(victim_ip='10.50.199.86')

# TCP SYN flood dataset
df = stage1.do_preprocessings(r'datasets/BOUN_DDoS dataset/BOUN_TCP_Anon.csv', begin=1000000)
flow_df = stage1.generate_flow_dataframe(df, chunk_size=10000)
flow_df.to_csv('datasets/TCP_SYN_FLOODING.csv', index=False)
plt.plot(flow_df['Mean_Time'], flow_df['SSIP'], color="green")
plt.plot(flow_df['Mean_Time'], flow_df['SSP'], color="red")
plt.show()
plt.plot(flow_df['Mean_Time'], flow_df['SDFB'], color="blue")
plt.show()
plt.plot(flow_df['Mean_Time'], flow_df['SFE'], color="yellow")
plt.show()
plt.plot(flow_df['Mean_Time'], flow_df['RPF'], color="purple")
plt.show()
plt.plot(flow_df['Mean_Time'], flow_df['Traffic_Type'], color="orange")
plt.show()
print()
################################################################################
# UDP flood dataset
df = stage1.do_preprocessings(r'datasets/BOUN_DDoS dataset/BOUN_UDP_Anon.csv')
flow_df = stage1.generate_flow_dataframe(df, chunk_size=10000)
flow_df.to_csv('datasets/UDP_FLOODING.csv', index=False)
plt.plot(flow_df['Mean_Time'], flow_df['SSIP'], color="green")
plt.plot(flow_df['Mean_Time'], flow_df['SSP'], color="red")
plt.show()
plt.plot(flow_df['Mean_Time'], flow_df['SDFB'], color="blue")
plt.show()
plt.plot(flow_df['Mean_Time'], flow_df['SFE'], color="yellow")
plt.show()
plt.plot(flow_df['Mean_Time'], flow_df['RPF'], color="purple")
plt.show()
plt.plot(flow_df['Mean_Time'], flow_df['Traffic_Type'], color="orange")
plt.show()


# attack_index_list = df.loc[df['Traffic_Type'] == MALICOUS_TRAFFIC, 'Time']
# textfile = open("attack_time_list.txt", "w")
# for element in attack_index_list:
#     textfile.write(str(element) + '\n')
# textfile.close()





###################################################################################################

# # Spot Check Algorithms
# models = []
# models.append(('LDA', LinearDiscriminantAnalysis()))
# models.append(('KNN', KNeighborsClassifier()))
# models.append(('CART', DecisionTreeClassifier()))
# models.append(('NB', GaussianNB()))

# # evaluate each model in turn
# results = []
# names = []
# for name, model in models:
#     kfold = StratifiedKFold(n_splits=10, random_state=1, shuffle=True)
#     cv_results = cross_val_score(model, X_train, Y_train, cv=kfold, scoring='accuracy')
#     results.append(cv_results)
#     names.append(name)
#     print('%s: %f (%f)' % (name, cv_results.mean(), cv_results.std()))
