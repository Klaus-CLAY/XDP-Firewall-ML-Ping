from sys import prefix
import matplotlib.pyplot as plt
import pandas as pd


if __name__ == '__main__':
    dataset_path = 'datasets/dump_4clients_0.2interval_final.csv'
    flow_df = pd.read_csv(dataset_path)
    plt_title = 'TCP SYN Flooding (custom Dataset)'
    prefix = 'custom_tcp'
    metrics = ['SSIP', 'SSP', 'SDFB', 'SFE', 'RPF']

    for metric in metrics:
        plt.plot(flow_df['Mean_Time'], flow_df[metric])
        plt.title(plt_title)
        plt.xlabel('time')
        plt.legend([metric], loc ="upper right")
        plt.gcf().set_size_inches(10, 6)
        plt.savefig(f'figs/{prefix}_{metric}.png', dpi=100)
        plt.clf()