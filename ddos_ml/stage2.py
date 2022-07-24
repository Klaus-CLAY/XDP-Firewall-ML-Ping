import pandas as pd
from sklearn.tree import DecisionTreeClassifier

def compare_results(a, b):
    cmp = []
    for i in range(len(a)):
        if a[i] != b[i]:
            cmp.append(i)
    
    return cmp



flow_df_train = pd.read_csv(r'datasets/TCP_SYN_FLOODING.csv')[:600]
x_train = flow_df_train[flow_df_train.columns.difference(['Traffic_Type', 'Mean_Time'])]
y_train = flow_df_train['Traffic_Type']

flow_df_test = pd.read_csv(r'datasets/TCP_SYN_FLOODING.csv')[600:]
x_test = flow_df_test[flow_df_test.columns.difference(['Traffic_Type', 'Mean_Time'])]
y_test = flow_df_test['Traffic_Type']

print(x_train)
print()
# print(y_train)

dtree = DecisionTreeClassifier()
dtree = dtree.fit(x_train, y_train)

y_test_predict = dtree.predict(x_test)

print(compare_results(list(y_test), list(y_test_predict)))
# print(list(y_test_predict))
# print('vs')
# print(list(y_test))


