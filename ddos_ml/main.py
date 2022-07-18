# import matplotlib.pyplot as plt
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

# time, frame_number, frame_length, src_ip, dst_ip, src_port, dst_port, syn, ack, rst, ttl, tcp_protocol

file2 = r"datasets/BOUN_DDoS dataset/BOUN_TCP_Anon.csv"
TARGET_IP = '10.50.199.86'
df = pd.read_csv(file2, low_memory=False, nrows=2000000)
df['Attack_Type'] = 'BENIGN'
# print(df)
df.loc[df['Destination_IP'] == TARGET_IP, 'Attack_Type'] = 'SYN_FLOOD'
df = df[["Time", "TTL", "SYN", "ACK",
                   "Attack_Type", "Source_ip", 'Frame_length']]
# print('\n2:')
# print(df.info())

df["SYN"] = df["SYN"].fillna(0)
df["ACK"] = df["ACK"].fillna(0)
df["SYN"] = df["SYN"].replace(['Set', 'Not set'], [1, 0])
df["ACK"] = df["ACK"].replace(['Set', 'Not set'], [1, 0])
df["Time"] = df["Time"].fillna(0)

# print('\n3:')
# print(df.info())

df["Time"] = df["Time"].astype(np.uint32)
S = []
packetno = 1
M = []
bits = 0
print(df)


# for i in range(1, len(df)):
#     if df.loc[i, 'Time'] >= (df.loc[i-1, 'Time'])+1 or df.loc[i, 'Attack'] != df.loc[i-1, 'Attack']:
#         M = set(M)
#         unique_ips = len(M)
#         Attack_type = df.loc[i, "Attack"]
#         S.append([packetno, unique_ips, bits, Attack_type])
#         packetno = 0
#         bits = 0
#         M = []
#     else:
#         bits += df.loc[i, 'Frame_length']
#         M.append(df.loc[i, 'Source_ip'])
#         packetno += 1
#         S.append([packetno, unique_ips, bits, Attack_type])
#         S = DataFrame(
#             S, columns=['packetno', 'unique_ips', 'bits', 'Attack_type'])
#         S = S.dropna()
#         print(S)
#         print(S.describe())
#         print(S.groupby("Attack_type").size())

###################################################################################################

# labels = 'TCPSYN', 'UDPFLOOD', 'BENIGN'
# sizes = [len(S[S["Attack_type"] == "TCPSYN"]), len(
#     S[S["Attack_type"] == "UDPFLOOD"]), len(S[S["Attack_type"] == "BENIGN"])]
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
