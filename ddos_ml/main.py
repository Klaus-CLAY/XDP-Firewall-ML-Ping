import matplotlib.pyplot as plt
import pandas as pd
# from pandas.plotting import scatter_matrix
# from matplotlib import pyplot
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
from pandas import DataFrame
# time, frame_number, frame_length, src_ip, dst_ip, src_port, dst_port, syn, ack, rst, ttl, tcp_protocol


def process_flow(df):
    log_row = dict()
    time_interval = df['Time'].max() - df['Time'].min()
    unique_src_ip_count = len(df['Source_ip'].unique())
    unique_src_port_count = len(df['Source_Port'].unique())

    log_row['SSIP'] = unique_src_ip_count / time_interval
    log_row['SSP'] = unique_src_port_count / time_interval
    # log_row['SDFP']
    # log_row['SDFB'] = df['Frame_length'].std()
    # log_row['SFE'] = len(df) / time_interval
    log_row['RPF'] = calc_pair_flow_ratio(df)

    return log_row


def calc_pair_flow_ratio(df):
    inbound_socks = set(df.groupby(['Source_ip', 'Source_Port']).count().index)
    outbound_socks = set(df.groupby(
        ['Destination_IP', 'Destination_Port']).count().index)

    return len(inbound_socks & outbound_socks) / len(inbound_socks)


dataset_file = r"datasets/BOUN_DDoS dataset/BOUN_TCP_Anon.csv"
TARGET_IP = '10.50.199.86'
df = pd.read_csv(dataset_file, nrows=6000000)[1000000:]
df['Attack_Type'] = 'BENIGN'
df.loc[df['Destination_IP'] == TARGET_IP, 'Attack_Type'] = 'TCP_SYN'
df = df[["Time", "Source_ip", 'Source_Port', 'Destination_IP',
         'Destination_Port', 'Frame_length', "Attack_Type"]]

print('malicious records count:', len(
    df[df['Attack_Type'] == 'TCP_SYN']), '/', len(df))
print(df)

# attack_index_list = df[df['Attack_Type'] == 'TCP_SYN'].index
# textfile = open("attack_index_list.txt", "w")
# for element in attack_index_list:
#     textfile.write(str(element) + '\n')
#     # textfile.write('\n')
# textfile.close()


# print(df.groupby('Source_ip').count())
# print(df.loc[(df['Source_ip'] == '10.50.197.71') | (df['Destination_IP'] == '10.50.197.71')])

# df["SYN"] = df["SYN"].fillna(0)
# df["ACK"] = df["ACK"].fillna(0)
# df["SYN"] = df["SYN"].replace(['Set', 'Not set'], [1, 0])
# df["ACK"] = df["ACK"].replace(['Set', 'Not set'], [1, 0])
# df["Time"] = df["Time"].fillna(0)

CHUNK_SIZE = 100000
log_list = []
for i in range(len(df)//CHUNK_SIZE):
    log_list.append(process_flow(df[CHUNK_SIZE*i:CHUNK_SIZE*(i+1)]))

log_df = pd.DataFrame(log_list)

plt.plot(log_df.index, log_df['SSIP'], color="green")
plt.plot(log_df.index, log_df['SSP'], color="red")
# plt.plot(log_df.index, log_df['SDFB'], color="blue")
# plt.plot(log_df.index, log_df['SFE'], color="yellow")
plt.show()
plt.plot(log_df.index, log_df['RPF'], color="purple")
plt.show()
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
