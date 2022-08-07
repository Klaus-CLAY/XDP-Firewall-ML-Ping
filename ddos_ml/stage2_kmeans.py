import pandas as pd
from sklearn.cluster import KMeans
from sklearn.model_selection import train_test_split
import pickle

def compare_results(a, b):
    cmp = []
    for i in range(len(a)):
        if a[i] != b[i]:
            cmp.append(i)
    
    return cmp


if __name__ == '__main__':
    flow_df = pd.read_csv(r'dump_4clients_0.2interval_fabbed.csv')
    x = flow_df[flow_df.columns.difference(['Traffic_Type', 'Mean_Time'])]
    y = flow_df['Traffic_Type']

    x_train, x_test, y_train, y_test = train_test_split(x, y, random_state=0, train_size = .65)

    print(x_train)
    print()
    # print(y_train)

    model = KMeans(n_clusters=2)
    model.fit(x_train)
    # dtree.save('dt_model.h5')

    # save
    with open('kmeans_model.pkl','wb') as f:
        pickle.dump(model,f)
    # load
    with open('kmeans_model.pkl', 'rb') as f:
        loaded_model = pickle.load(f)

    y_train_predict = loaded_model.predict(x_train)
    diff = compare_results(list(y_train), list(y_train_predict))
    print(f'accuracy train: {(1 - len(diff) / len(y_train))*100}%')

    y_test_predict = loaded_model.predict(x_test)
    diff = compare_results(list(y_test), list(y_test_predict))
    print(f'accuracy test: {(1 - len(diff) / len(y_test))*100}%')
    # print(list(y_test_predict))
    # print('vs')
    # print(list(y_test))


