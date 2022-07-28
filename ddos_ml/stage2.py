import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
import pickle

def compare_results(a, b):
    cmp = []
    for i in range(len(a)):
        if a[i] != b[i]:
            cmp.append(i)
    
    return cmp


if __name__ == '__main__':
    flow_df = pd.read_csv(r'dump_4clients_0.2interval.csv')
    x = flow_df[flow_df.columns.difference(['Traffic_Type', 'Mean_Time'])]
    y = flow_df['Traffic_Type']

    x_train, x_test, y_train, y_test = train_test_split(x, y, random_state=0, train_size = .65)

    # flow_df_train = pd.read_csv(r'datasets/TCP_SYN_FLOODING.csv')[:600]
    # x_train = flow_df_train[flow_df_train.columns.difference(['Traffic_Type', 'Mean_Time'])]
    # y_train = flow_df_train['Traffic_Type']

    # flow_df_test = pd.read_csv(r'datasets/TCP_SYN_FLOODING.csv')[600:]
    # x_test = flow_df_test[flow_df_test.columns.difference(['Traffic_Type', 'Mean_Time'])]
    # y_test = flow_df_test['Traffic_Type']

    print(x_train)
    print()
    # print(y_train)

    dtree = DecisionTreeClassifier()
    dtree = dtree.fit(x_train, y_train)
    # dtree.save('dt_model.h5')

    # save
    with open('dt_model.pkl','wb') as f:
        pickle.dump(dtree,f)
    # load
    with open('dt_model.pkl', 'rb') as f:
        loaded_model = pickle.load(f)

    y_test_predict = loaded_model.predict(x_test)

    diff = compare_results(list(y_test), list(y_test_predict))
    print(f'accuracy: {(1 - len(diff) / len(y_test))*100}%')
    # print(list(y_test_predict))
    # print('vs')
    # print(list(y_test))


