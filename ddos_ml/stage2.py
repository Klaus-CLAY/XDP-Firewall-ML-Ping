import pandas as pd
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
import pickle

def compare_results(actual_res, predicted_res):
    assert(len(actual_res) == len(predicted_res))
    l = len(predicted_res)
    tn, tp, fn, fp = 0, 0, 0, 0

    for i in range(l):
        if actual_res[i] == predicted_res[i]:
            if predicted_res[i] == 1:
                tp += 1
            else:
                tn += 1
        else:
            if predicted_res[i] == 1:
                fp += 1
            else:
                fn += 1
    # print(f'tp: {tp}\ttn: {tn}\tfp: {fp}\tfn: {fn}')
    print(f'precision: {tp/(tp+fp)}')
    print(f'accuracy: {(tp + tn)/l}')
    print(f'sensitivity (TPR): {tp/(tp+fn)}')
    print(f'specificity (TNR): {tn/(tn+fp)}')




if __name__ == '__main__':
    # dataset_path = 'dump_4clients_0.2interval.csv'
    dataset_path = 'datasets/UDP_FLOODING.csv'
    flow_df = pd.read_csv(dataset_path)
    flow_df = pd.concat([flow_df, pd.read_csv('datasets/TCP_SYN_FLOODING.csv')])
    x = flow_df[flow_df.columns.difference(['Traffic_Type', 'Mean_Time'])]
    y = flow_df['Traffic_Type']

    x_train, x_test, y_train, y_test = train_test_split(x, y, random_state=1, train_size = .65)

    dtree = DecisionTreeClassifier()
    dtree = dtree.fit(x_train, y_train)

    # save
    with open('dt_model_tcp_udp.pkl','wb') as f:
        pickle.dump(dtree,f)
    # load
    with open('dt_model_tcp_udp.pkl', 'rb') as f:
        loaded_model = pickle.load(f)

    y_test_predict = loaded_model.predict(x_test)

    compare_results(list(y_test), list(y_test_predict))



