import matplotlib.pyplot as plt
# from pandas import read_csv
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


# TIME_INTERVAL = 1  # 1 second


def process_flow(df):
    TIME_INTERVAL = df['Time'].max() - df['Time'].min()
    log_row = dict()
    # print(len(df))
    unique_src_ip_count = len(df['Source_ip'].unique())
    unique_src_port_count = len(df['Source_Port'].unique())

    # print(unique_src_port_count)

    log_row['SSIP'] = unique_src_ip_count / TIME_INTERVAL
    log_row['SSP'] = unique_src_port_count / TIME_INTERVAL
    # log_row['SDFP']
    log_row['SDFB'] = df['Frame_length'].std()
    log_row['SFE'] = len(df) / TIME_INTERVAL

    # int_flow_cnt = count_interactive_flows(df)
    # print(f'interactive flow count: {int_flow_cnt}')
    # log_row['RPF'] = 2*int_flow_cnt/len(df)
    return log_row
    # print(log_row)

# TODO: checking unique ips would be much faster!
def count_interactive_flows(df):
    count = 0
    # unique_ips = df['Source_ip'].unique()
    # print('hiii')
    print('start...')
    
    a = df.apply(lambda row: check_interactive_flow(df, row['Source_ip'], row['Source_Port']), axis=1)
    print(a)
    print('end...')



    # iii=0

    # for _, row in df.iterrows():

    #     print(f'iter_{iii}')
    #     # print(f'index: {index}, row: {row}')
    #     match_count = len(df.loc[(df['Destination_IP'] == row['Source_ip']) & (
    #         df['Destination_Port'] == row['Source_Port'])])
    #     if match_count > THRESHOLD:
    #         count += 1

    #     df.drop(df[(df['Source_ip'] == row['Source_ip']) & (
    #         df['Source_Port'] == row['Source_Port'])].index, inplace=True)
    #     # print(df.loc[(df['Destination_IP'] == row['Source_ip']) & (df['Destination_Port'] == row['Source_Port'])])
    #     # print()
    #     # break
    #     iii += 1
    return count

def check_interactive_flow(df, source_ip, source_port):
    THRESHOLD = 0
    print('.',end='')

    match_count = len(df.loc[(df['Destination_IP'] == source_ip) & (
            df['Destination_Port'] == source_port)])
    if match_count > THRESHOLD:
        return 1
    else:
        return 0


# time, frame_number, frame_length, src_ip, dst_ip, src_port, dst_port, syn, ack, rst, ttl, tcp_protocol

dataset_file = r"datasets/BOUN_DDoS dataset/BOUN_TCP_Anon.csv"
TARGET_IP = '10.50.199.86'
df = pd.read_csv(dataset_file, nrows=4000000)[2000000:]
df['Attack_Type'] = 'BENIGN'
# print(df)
df.loc[df['Destination_IP'] == TARGET_IP, 'Attack_Type'] = 'TCP_SYN'
df = df[["Time", "Source_ip", 'Source_Port', 'Destination_IP',
         'Destination_Port', 'Frame_length', "Attack_Type"]]
# print('\n2:')

print('malicious records count:', len(df[df['Attack_Type'] == 'TCP_SYN']), '/', len(df))
attack_index_list = df[df['Attack_Type'] == 'TCP_SYN'].index


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

# # print('\n3:')
# # print(df.info())

# df["Time"] = df["Time"].astype(np.uint32)
# S = []
# packetno = 1
# M = []
# bits = 0
# print(df.loc[(df['Attack_Type'] == 'TCP_SYN') & (df['Destination_Port'] == 80)])
# # print(df[df['Attack_Type'] == 'TCP_SYN' and df['Destination_Port'] == 80])
chunk_size = 20000
log_list = []
for i in range(len(df)//chunk_size):
    # print(f'iter_{i}')
    log_list.append(process_flow(df[chunk_size*i:chunk_size*(i+1)]))

# print(log_list)
log_df = pd.DataFrame(log_list)
# print()
print(log_df)

plt.plot(log_df.index, log_df['SSIP'], color="green")
plt.plot(log_df.index, log_df['SSP'], color="red")
plt.plot(log_df.index, log_df['SDFB'], color="blue")
# plt.plot(log_df.index, log_df['SFE'], color="yellow")
plt.show()

# log_df = pd.DataFrame(columns=['SSIP', 'SSP', 'SDFP', 'SDFB', 'SFE', 'RPF'])
# data = [['SSIP', 10], ['SSP', 10], ['SDFP', 10], ['SDFB', 10], ['SFE', 10], ['RPF', 10]]
# log_df.append(data, ignore_index=True)
# print(log_df)


print('*************************************************************')

# for i in range(1, 10):
#     print(f'it_{i}')
#     cond0 = i == 1
#     cond1 = df.loc[i, 'Time'] >= (df.loc[i-1, 'Time'])+1
#     cond2 = df.loc[i, 'Attack_Type'] != df.loc[i-1, 'Attack_Type']
#     if cond0 or cond1 or cond2:
#         M = set(M)
#         unique_ips = len(M)
#         attack = df.loc[i, "Attack_Type"]
#         S.append([packetno, unique_ips, bits, attack])
#         packetno = 0
#         bits = 0
#         M = []
#     else:
#         bits += df.loc[i, 'Frame_length']
#         M.append(df.loc[i, 'Source_ip'])
#         packetno += 1
#         S.append([packetno, unique_ips, bits, attack])
#         S = DataFrame(
#             S, columns=['packetno', 'unique_ips', 'bits', 'attack'])
#         S = S.dropna()
#         print(S)
#         # print(S.describe())
#         # print(S.groupby("attack").size())


###################################################################################################

# labels = 'TCP_SYN', 'UDP_FLOOD', 'BENIGN'
# sizes = [len(S[S["attack"] == "TCP_SYN"]), len(
#     S[S["attack"] == "UDPFLOOD"]), len(S[S["attack"] == "BENIGN"])]
# colors = ['gold', 'yellowgreen', 'lightcoral',
#           'lightskyblue', 'yellow', 'purple', 'grey']
# explode = (0, 0, 0)  # explode 1st slice

# # Plot
# plt.rcParams.update({'font.size': 10})
# plt.figure(figsize=(8, 8))
# plt.pie(sizes, explode=explode, labels=labels, colors=colors,
#         autopct='%1.1f%%', shadow=True, startangle=140)
# plt.axis('equal')
# plt.show()


###################################################################################################

# scatter_matrix(S)
# pyplot.show()

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
