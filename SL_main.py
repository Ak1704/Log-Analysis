import streamlit as st
from Log_File_Handling.Parse_logs import *
import plotly.express as ff
st.set_page_config(page_title="Log File Analysis",layout='wide')


def result_container(df: pd.DataFrame, text: str, key: int = 0):
    with st.container(height=350):
        col1, col2 = st.columns([5,6])
        with col1:
            st.subheader(text)
            st.write(df)
        with col2:
            fig = ff.line(df,x=df.index, y=df['Request_Count'])
            if key != 0:
                st.plotly_chart(fig, use_container_width=True, key=key)
            else:
                st.plotly_chart(fig, use_container_width=True)


def save_file(cnt_req: pd.DataFrame, freq_endpoint: pd.DataFrame, bf_freq: pd.DataFrame, file_name: str):
    with open(f'{file_name}', 'w') as f:
        cnt_req.to_csv(f)
        f.write("\n End Point Frequency")

    with open(f'{file_name}', 'a') as f:
        freq_endpoint.to_csv(f)
        f.write("\n Brute Force Frequency")
        bf_freq.to_csv(f)


def call_functions_app(input_file: str, threshold: int, file_name: str=""):
    log_df = read_logs(input_file)

    # return number of calls made from each IP
    req_freq = count_cols(log_df, 'client')
    req_freq = req_freq.set_axis(['Request_Count'], axis=1)
    result_container(req_freq, 'Request Count')

    # return highest accessed endpoint
    end_point_val = log_df['request'].value_counts().to_frame().reset_index()
    end_point_val = end_point_val.set_axis(['Endpoint','Request_Count'], axis=1)
    max_end_point = end_point_val.iloc[end_point_val['Request_Count'].idxmax()]
    result_container(end_point_val, 'Frequency of Calls each endpoint')
    st.write(f'{max_end_point["Endpoint"]} (Accessed {max_end_point["Request_Count"]} times)')

    # return brute force login attempt
    fail_login_cnt, fail_login_below_threshold = cnt_failed_attempt(log_df, threshold)
    fail_login_cnt = fail_login_cnt.set_axis(['Request_Count'], axis=1)
    fail_login_below_threshold = fail_login_below_threshold.set_axis(['Request_Count'], axis=1)
    if not fail_login_cnt.empty:
        result_container(fail_login_cnt, 'All failed Authorisation Ip addresses')
    if not fail_login_below_threshold.empty:
        result_container(fail_login_below_threshold, 'Brute Force Flags', 1)
    if file_name!="":
        save_file(req_freq, end_point_val, fail_login_below_threshold, file_name)
    else:
        write_to_csv(req_freq, end_point_val, fail_login_below_threshold)


col1, col2 = st.columns([3,7])
with col1:
    st.title('Log Analysis')
    input_file = st.text_input("Input Log File")
    threshold = st.text_input('Threshold', value=10)
    file_name = st.text_input('Save to:')
    submit1 = st.button('submit')
if submit1:
    with col2:
        if not input_file:
            st.error('Require input_file')
        elif file_name!="":
            call_functions_app(input_file, int(threshold), file_name)
        else:
            call_functions_app(input_file, int(threshold))
