import argparse
from Log_File_Handling.Parse_logs import *

def call_functions(input_file: str, threshold: int = 10):
    log_df = read_logs(input_file)

    #return number of calls made from each IP
    print('Requests per IP Address')
    req_freq = count_cols(log_df, 'client').reset_index()
    req_freq = req_freq.set_axis(['IP','Request_Count'], axis=1)
    print(req_freq)

    #return highest accessed endpoint
    end_point_val = log_df['request'].value_counts().to_frame().reset_index()
    end_point_val = end_point_val.set_axis(['Endpoint', 'Request_Count'], axis=1)
    max_end_point = end_point_val.iloc[end_point_val['Request_Count'].idxmax()]
    print('Most Frequently Accessed Endpoint:')
    print(f'{max_end_point["Endpoint"]} (Accessed {max_end_point["Request_Count"]} times)')

    # return brute force login attempt
    fail_login_cnt, fail_login_below_threshold = cnt_failed_attempt(log_df, threshold)
    fail_login_cnt = fail_login_cnt.set_axis(['IP', 'Request_Count'])
    print("Suspicious Activity Detected:")
    print(fail_login_below_threshold)
    write_to_csv(req_freq, end_point_val, fail_login_below_threshold)


def main():
    parser = argparse.ArgumentParser(description ='Parse Log files from commmand line')

    parser.add_argument('input_file', type=str, help="Path of input file ")
    parser.add_argument('threshold', type=int, help="Threshold for brute force")

    arguments = parser.parse_args()
    if not arguments.input_file:
        raise 'Input Not provided'
    if arguments.threshold:
        call_functions(arguments.input_file, arguments.threshold)
    else:
        call_functions(arguments.input_file)


if __name__ == '__main__':
    main()

