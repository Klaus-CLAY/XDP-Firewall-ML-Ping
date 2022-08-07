import pandas as pd
from sklearn.cluster import KMeans
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
    flow_df = pd.read_csv(r'datasets/dump_4clients_0.2interval_final.csv')
    x = flow_df[flow_df.columns.difference(['Traffic_Type', 'Mean_Time'])]
    y = flow_df['Traffic_Type']
    x_train, x_test, y_train, y_test = train_test_split(x, y, random_state=0, train_size = .65)

    model = KMeans(n_clusters=2)
    # FIXME: cluster indexes may vary by each run. make sure to get cluster 1 as MALICIOUS_TRAFFIC
    model.fit(x_train)

    # save
    with open('kmeans_model.pkl','wb') as f:
        pickle.dump(model,f)
    # load
    with open('kmeans_model.pkl', 'rb') as f:
        loaded_model = pickle.load(f)

    y_train_predict = loaded_model.predict(x_train)
    print('train stats:')
    compare_results(list(y_train), list(y_train_predict))

    y_test_predict = loaded_model.predict(x_test)
    print('\ntest stats:')
    compare_results(list(y_test), list(y_test_predict))

