import re
import pandas as pd


def read_logs(file_name: str):
    regex1 = '(?P<client>\S+) - (?P<userid>\S+) \[(?P<datetime>[^\]]+)] "(?P<method>\S+) (?P<request>\S+) HTTP/\S+" (?P<status>\d+) (?P<size>\d+)(?: "(?P<msg>[^"]+)")?'
    columns = ['client', 'userid', 'datetime', 'method', 'request', 'status', 'size', 'msg']
    with open(file_name) as read_file:
        cnt = 0
        lines = []
        for line in read_file.readlines():
            try:
                log = re.findall(regex1, line)[0]
                lines.append(log)
            except Exception as e:
                print(e)
                continue
            cnt += 1
        print('count:', cnt)
    df = pd.DataFrame(lines, columns=columns)
    df = df.drop(['userid'], axis=1)
    #df.to_csv('./Log_files/test.csv')
    return df


def count_cols(df: pd.DataFrame, column: str):
    return pd.DataFrame(df[column].value_counts()).sort_values('count', ascending=False)


def frequency_ip_status(df: pd.DataFrame):
    all_status = df['status'].unique()
    cols = ['ip']+all_status
    gp_ip = pd.DataFrame(df.groupby(['client'])['status'].value_counts(), columns=['count'])
    gp_ip.index = gp_ip.index.set_names(['Client', 'Status'])
    gp_ip.reset_index(inplace=True)
    return gp_ip.sort_values(by='count', ascending=False).reset_index().drop(['index'],axis=1)


def cnt_failed_attempt(df: pd.DataFrame, threshold: int = 10):
    failed_df = df[(df['status'] == '401') | (df['msg'] == 'Invalid credentials')]
    failed_df_cn = failed_df['client'].value_counts().to_frame()
    return failed_df_cn, failed_df_cn[(failed_df_cn['count'] >= threshold)]


def write_to_csv(cnt_req: pd.DataFrame, freq_endpoint: pd.DataFrame, bf_freq: pd.DataFrame):
    with open('Log_files/log_analysis_results.csv', 'w') as f:
        cnt_req.to_csv(f)
        f.write("\n")

    with open('Log_files/log_analysis_results.csv', 'a') as f:
        freq_endpoint.to_csv(f)
        bf_freq.to_csv(f)
