import pandas as pd
import numpy as np
import random

def generate_ip():
    return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def generate_normal_traffic(n=1000):
    data = []
    protocols = ['TCP', 'UDP', 'ICMP']
    ports = [80, 443, 53, 22, 21, 25]
    
    for _ in range(n):
        data.append({
            'src_ip': generate_ip(),
            'dst_ip': generate_ip(),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice(ports),
            'protocol': random.choice(protocols),
            'packet_size': random.randint(64, 1500),
            'duration': round(random.uniform(0.001, 5.0), 3),
            'packets_sent': random.randint(1, 100),
            'packets_received': random.randint(1, 100),
            'bytes_sent': random.randint(100, 10000),
            'bytes_received': random.randint(100, 10000),
            'syn_flag': random.choice([0, 1]),
            'ack_flag': random.choice([0, 1]),
            'fin_flag': random.choice([0, 1]),
            'rst_flag': 0,
            'label': 'normal'
        })
    return data

def generate_port_scan(n=200):
    data = []
    attacker = generate_ip()
    target = generate_ip()
    
    for _ in range(n):
        data.append({
            'src_ip': attacker,
            'dst_ip': target,
            'src_port': random.randint(40000, 50000),
            'dst_port': random.randint(1, 65535),
            'protocol': 'TCP',
            'packet_size': 60,
            'duration': 0.001,
            'packets_sent': 1,
            'packets_received': 0,
            'bytes_sent': 60,
            'bytes_received': 0,
            'syn_flag': 1,
            'ack_flag': 0,
            'fin_flag': 0,
            'rst_flag': random.choice([0, 1]),
            'label': 'port_scan'
        })
    return data

def generate_ddos(n=300):
    data = []
    target = generate_ip()
    
    for _ in range(n):
        data.append({
            'src_ip': generate_ip(),
            'dst_ip': target,
            'src_port': random.randint(1024, 65535),
            'dst_port': random.choice([80, 443]),
            'protocol': 'TCP',
            'packet_size': random.randint(500, 1500),
            'duration': round(random.uniform(0.001, 0.1), 3),
            'packets_sent': random.randint(100, 1000),
            'packets_received': 0,
            'bytes_sent': random.randint(50000, 500000),
            'bytes_received': 0,
            'syn_flag': 1,
            'ack_flag': 0,
            'fin_flag': 0,
            'rst_flag': 0,
            'label': 'ddos'
        })
    return data

def main():
    all_data = []
    all_data.extend(generate_normal_traffic(1000))
    all_data.extend(generate_port_scan(200))
    all_data.extend(generate_ddos(300))
    
    df = pd.DataFrame(all_data)
    df = df.sample(frac=1).reset_index(drop=True)
    
    df.to_csv('data/samples/sample_network_traffic.csv', index=False)
    test_df = df.sample(n=100).reset_index(drop=True)
    test_df.to_csv('data/samples/test_traffic.csv', index=False)
    
    print(f"Generated {len(df)} records")
    print(f"Saved to data/samples/sample_network_traffic.csv")
    print(f"Test file: data/samples/test_traffic.csv")
    print("\nDistribution:")
    print(df['label'].value_counts())

if __name__ == "__main__":
    main()
