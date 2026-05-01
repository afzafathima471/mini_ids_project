"""Generate a sample network traffic dataset for training and demo."""
import pandas as pd
import numpy as np
import os

np.random.seed(42)
n = 2000

protocols = ['tcp', 'udp', 'icmp']
services  = ['http', 'ftp', 'smtp', 'ssh', 'dns', 'telnet', 'pop3', 'imap']
flags     = ['SF', 'S0', 'REJ', 'RSTO', 'SH', 'S1', 'S2', 'RSTOS0', 'S3', 'OTH']
labels    = ['normal', 'DoS', 'Probe', 'R2L', 'U2R']
weights   = [0.60, 0.20, 0.10, 0.06, 0.04]

rows = []
for _ in range(n):
    label = np.random.choice(labels, p=weights)
    if label == 'normal':
        row = dict(
            duration=np.random.randint(0, 300),
            protocol_type=np.random.choice(protocols),
            service=np.random.choice(services),
            flag=np.random.choice(['SF', 'S1']),
            src_bytes=np.random.randint(100, 50000),
            dst_bytes=np.random.randint(100, 50000),
            land=0, wrong_fragment=0, urgent=0,
            hot=np.random.randint(0, 5),
            num_failed_logins=0, logged_in=1,
            num_compromised=0, root_shell=0, su_attempted=0,
            num_root=0, num_file_creations=np.random.randint(0,3),
            num_shells=0, num_access_files=0,
            count=np.random.randint(1, 50),
            srv_count=np.random.randint(1, 50),
            serror_rate=round(np.random.uniform(0, 0.1), 2),
            rerror_rate=round(np.random.uniform(0, 0.1), 2),
            same_srv_rate=round(np.random.uniform(0.8, 1.0), 2),
            diff_srv_rate=round(np.random.uniform(0, 0.2), 2),
            dst_host_count=np.random.randint(100, 255),
            dst_host_srv_count=np.random.randint(50, 255),
            dst_host_same_srv_rate=round(np.random.uniform(0.7, 1.0), 2),
            dst_host_diff_srv_rate=round(np.random.uniform(0, 0.3), 2),
            label=label
        )
    elif label == 'DoS':
        row = dict(
            duration=0, protocol_type='tcp',
            service=np.random.choice(['http', 'smtp']),
            flag=np.random.choice(['S0', 'REJ']),
            src_bytes=np.random.randint(0, 500),
            dst_bytes=0,
            land=0, wrong_fragment=np.random.randint(0,3), urgent=0,
            hot=0, num_failed_logins=0, logged_in=0,
            num_compromised=0, root_shell=0, su_attempted=0,
            num_root=0, num_file_creations=0, num_shells=0, num_access_files=0,
            count=np.random.randint(400, 512),
            srv_count=np.random.randint(400, 512),
            serror_rate=round(np.random.uniform(0.8, 1.0), 2),
            rerror_rate=0.0,
            same_srv_rate=round(np.random.uniform(0.9, 1.0), 2),
            diff_srv_rate=0.0,
            dst_host_count=255, dst_host_srv_count=255,
            dst_host_same_srv_rate=1.0, dst_host_diff_srv_rate=0.0,
            label=label
        )
    elif label == 'Probe':
        row = dict(
            duration=np.random.randint(0, 10),
            protocol_type=np.random.choice(['tcp','udp']),
            service=np.random.choice(services),
            flag=np.random.choice(['SF','S0','REJ']),
            src_bytes=np.random.randint(0, 1000),
            dst_bytes=np.random.randint(0, 1000),
            land=0, wrong_fragment=0, urgent=0,
            hot=0, num_failed_logins=0, logged_in=0,
            num_compromised=0, root_shell=0, su_attempted=0,
            num_root=0, num_file_creations=0, num_shells=0, num_access_files=0,
            count=np.random.randint(100, 512),
            srv_count=np.random.randint(1, 50),
            serror_rate=round(np.random.uniform(0, 0.5), 2),
            rerror_rate=round(np.random.uniform(0, 0.5), 2),
            same_srv_rate=round(np.random.uniform(0, 0.5), 2),
            diff_srv_rate=round(np.random.uniform(0.5, 1.0), 2),
            dst_host_count=np.random.randint(150, 255),
            dst_host_srv_count=np.random.randint(1, 50),
            dst_host_same_srv_rate=round(np.random.uniform(0, 0.3), 2),
            dst_host_diff_srv_rate=round(np.random.uniform(0.5, 1.0), 2),
            label=label
        )
    elif label == 'R2L':
        row = dict(
            duration=np.random.randint(1, 100),
            protocol_type='tcp',
            service=np.random.choice(['ftp','telnet','smtp']),
            flag='SF',
            src_bytes=np.random.randint(1000, 20000),
            dst_bytes=np.random.randint(100, 5000),
            land=0, wrong_fragment=0, urgent=0,
            hot=np.random.randint(1, 10),
            num_failed_logins=np.random.randint(1, 5),
            logged_in=0,
            num_compromised=0, root_shell=0, su_attempted=0,
            num_root=0, num_file_creations=0, num_shells=0, num_access_files=0,
            count=np.random.randint(1, 20),
            srv_count=np.random.randint(1, 20),
            serror_rate=0.0, rerror_rate=0.0,
            same_srv_rate=round(np.random.uniform(0.5, 1.0), 2),
            diff_srv_rate=round(np.random.uniform(0, 0.5), 2),
            dst_host_count=np.random.randint(10, 100),
            dst_host_srv_count=np.random.randint(1, 50),
            dst_host_same_srv_rate=round(np.random.uniform(0.5, 1.0), 2),
            dst_host_diff_srv_rate=round(np.random.uniform(0, 0.5), 2),
            label=label
        )
    else:  # U2R
        row = dict(
            duration=np.random.randint(1, 50),
            protocol_type='tcp',
            service=np.random.choice(['telnet','ftp','ssh']),
            flag='SF',
            src_bytes=np.random.randint(100, 5000),
            dst_bytes=np.random.randint(100, 5000),
            land=0, wrong_fragment=0, urgent=0,
            hot=np.random.randint(5, 20),
            num_failed_logins=np.random.randint(0, 2),
            logged_in=1,
            num_compromised=np.random.randint(1, 10),
            root_shell=1, su_attempted=np.random.randint(0,1),
            num_root=np.random.randint(1, 5),
            num_file_creations=np.random.randint(1, 5),
            num_shells=np.random.randint(1, 3),
            num_access_files=np.random.randint(1, 5),
            count=np.random.randint(1, 10),
            srv_count=np.random.randint(1, 10),
            serror_rate=0.0, rerror_rate=0.0,
            same_srv_rate=round(np.random.uniform(0.5, 1.0), 2),
            diff_srv_rate=round(np.random.uniform(0, 0.5), 2),
            dst_host_count=np.random.randint(10, 100),
            dst_host_srv_count=np.random.randint(1, 30),
            dst_host_same_srv_rate=round(np.random.uniform(0.5, 1.0), 2),
            dst_host_diff_srv_rate=round(np.random.uniform(0, 0.5), 2),
            label=label
        )
    rows.append(row)

df = pd.DataFrame(rows)
os.makedirs('data', exist_ok=True)
df.to_csv('data/network_traffic.csv', index=False)
print(f"Dataset saved: data/network_traffic.csv  ({len(df)} rows)")
