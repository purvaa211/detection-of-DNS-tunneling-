"""
Script to generate realistic, scientifically sound DNS datasets for testing and demonstration.
"""

import random
import string
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import math
from collections import Counter


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = -sum((cnt / length) * math.log2(cnt / length) for cnt in counts.values())
    return round(float(entropy), 4)


def generate_normal_domains():
    legit_second_level = [
        "google", "youtube", "microsoft", "apple", "amazon", "github", "wikipedia",
        "cloudflare", "netflix", "linkedin", "zoom", "spotify", "reddit", "twitter",
        "office365", "facebook", "dropbox", "salesforce", "slack", "gitlab", "medium",
        "adobe", "bing", "yahoo", "cnn", "nytimes", "stackoverflow", "docker", "python"
    ]
    tlds = ["com", "org", "net", "edu", "io", "gov", "co.in", "ac.uk"]
    subdomains = [
        "", "www", "api", "cdn", "mail", "auth", "dev", "assets", "static",
        "img", "login", "docs", "portal", "cloud", "sync", "v1.api", "secure"
    ]
    
    normal_list = []
    for _ in range(900):
        sld = random.choice(legit_second_level)
        tld = random.choice(tlds)
        sub = random.choice(subdomains)
        if sub:
            query = f"{sub}.{sld}.{tld}"
        else:
            query = f"{sld}.{tld}"
        # occasional CDN hash subdomains (benign but slight entropy)
        if random.random() < 0.08:
            cdn_hash = ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(6, 12)))
            query = f"{cdn_hash}.cdn.{sld}.{tld}"
        normal_list.append(query)
    return normal_list


def generate_tunneling_domains():
    c2_domains = ["dnscat2.net", "iodinetunnel.org", "tunnelc2.biz", "data-exfil.com", "ns1.shieldcorp.net"]
    tunnel_list = []
    
    # 1. Base32 / Hex DNSCat2 queries (high entropy, long, automated)
    for _ in range(250):
        c2 = random.choice(c2_domains)
        chunk_len = random.randint(35, 75)
        # Hex or Base32 chunks
        if random.random() < 0.6:
            chars = string.hexdigits.lower()[:16]
        else:
            chars = "abcdefghijklmnopqrstuvwxyz234567"
        payload = ''.join(random.choices(chars, k=chunk_len))
        seq = random.randint(100, 9999)
        query = f"dnscat.{seq}.{payload}.{c2}"
        tunnel_list.append(query)

    # 2. Iodine / Base64 queries
    for _ in range(150):
        c2 = random.choice(c2_domains)
        chunk_len = random.randint(40, 90)
        chars = string.ascii_letters + string.digits
        payload = ''.join(random.choices(chars, k=chunk_len))
        query = f"v1.{payload}.{c2}"
        tunnel_list.append(query)

    return tunnel_list


def build_dataset(num_normal=850, num_tunnel=350, seed=42):
    random.seed(seed)
    np.random.seed(seed)

    normal_queries = generate_normal_domains()[:num_normal]
    tunnel_queries = generate_tunneling_domains()[:num_tunnel]

    records = []
    # Interleave realistically: normal queries follow bursty human intervals (Poisson/Exponential ~ 0.2 to 5.0 sec)
    # Tunnel queries arrive in bursts or tight beaconing (0.02 to 0.25 sec)
    
    current_time = datetime(2026, 10, 18, 9, 30, 0)
    
    # Mix records: chunks of normal, then occasional tunnel bursts
    all_items = [(q, 'Normal') for q in normal_queries] + [(q, 'Suspicious') for q in tunnel_queries]
    random.shuffle(all_items)

    rec_types_normal = ['A', 'A', 'A', 'AAAA', 'CNAME', 'HTTPS']
    rec_types_tunnel = ['TXT', 'TXT', 'A', 'CNAME']

    for query, label in all_items:
        if label == 'Normal':
            # Human web browsing: exponential interval with mean ~ 1.2s, plus occasional idle pause
            iat = float(np.random.exponential(scale=1.1)) + 0.05
            if random.random() < 0.05:
                iat += random.uniform(3.0, 10.0)
            rec_type = random.choice(rec_types_normal)
        else:
            # Automated tunneling: tight loop or fixed beacon with slight jitter (0.02 to 0.35s)
            iat = float(np.random.exponential(scale=0.12)) + 0.02
            rec_type = random.choice(rec_types_tunnel)

        current_time += timedelta(seconds=iat)
        ent = shannon_entropy(query)
        q_len = len(query)

        records.append({
            "timestamp": current_time.strftime("%Y-%m-%d %H:%M:%S"),
            "query": query,
            "record_type": rec_type,
            "query_length": q_len,
            "entropy": ent,
            "inter_arrival_time": round(iat, 4),
            "label": label
        })

    # Sort strictly by timestamp
    df = pd.DataFrame(records)
    df['timestamp_dt'] = pd.to_datetime(df['timestamp'])
    df = df.sort_values(by='timestamp_dt').reset_index(drop=True)
    df.drop(columns=['timestamp_dt'], inplace=True)
    return df


if __name__ == "__main__":
    import os
    os.makedirs("data", exist_ok=True)

    # 1. Standard course project balanced dataset
    df_std = build_dataset(num_normal=850, num_tunnel=350, seed=42)
    df_std.to_csv("data/sample_dns_traffic.csv", index=False)
    print(f"Generated data/sample_dns_traffic.csv: {len(df_std)} rows")

    # 2. High-intensity attack scenario
    df_high = build_dataset(num_normal=300, num_tunnel=500, seed=101)
    df_high.to_csv("data/sample_high_entropy_tunneling.csv", index=False)
    print(f"Generated data/sample_high_entropy_tunneling.csv: {len(df_high)} rows")

    # 3. Normal workday enterprise traffic
    df_norm = build_dataset(num_normal=980, num_tunnel=20, seed=202)
    df_norm.to_csv("data/sample_normal_workday.csv", index=False)
    print(f"Generated data/sample_normal_workday.csv: {len(df_norm)} rows")
