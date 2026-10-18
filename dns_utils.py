"""
DNS Utilities Module for DNS Tunneling Detection Project.

Calculates Shannon Entropy, Inter-Arrival Times (IAT), and structural DNS features
for Probability and Statistics analysis.
"""

import math
import re
from collections import Counter
from datetime import datetime
import pandas as pd
import numpy as np


def shannon_entropy(text: str) -> float:
    """
    Computes Shannon Entropy in bits per character for a given string:
        H(X) = - sum(p_i * log2(p_i))
    where p_i is the relative frequency of character i.

    Higher entropy (close to 4.0 - 5.0 bits) indicates random/encrypted/encoded characters (e.g., base64/hex tunneling).
    Lower entropy (typically 2.0 - 3.2 bits) indicates natural language domain names.
    """
    if not text:
        return 0.0
    text = str(text).strip()
    length = len(text)
    if length <= 1:
        return 0.0

    counts = Counter(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(float(entropy), 4)


def extract_subdomain(domain: str) -> str:
    """
    Extracts the subdomain component of a domain name.
    e.g. 'data123.tunnel.example.com' -> 'data123.tunnel'
         'google.com' -> ''
    """
    if not domain or not isinstance(domain, str):
        return ""
    parts = domain.strip().rstrip('.').split('.')
    if len(parts) > 2:
        return '.'.join(parts[:-2])
    return ""


def process_dns_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Enriches a raw or uploaded DNS traffic DataFrame with statistical features:
    - query_length: Total length of domain name
    - subdomain_length: Length of subdomain payload
    - entropy: Shannon entropy of the full query
    - subdomain_entropy: Shannon entropy of the subdomain portion
    - digit_ratio: Proportion of numerical characters (0-9)
    - inter_arrival_time: Time difference (seconds) between successive queries
    - label: 'Normal' or 'Suspicious'
    """
    df = df.copy()

    # Normalize column names to lowercase and strip whitespace
    df.columns = [str(c).strip().lower().replace(" ", "_") for c in df.columns]

    # Map common aliases for query column
    query_col = None
    for alias in ['query', 'domain', 'dns_query', 'name', 'domain_name', 'query_name']:
        if alias in df.columns:
            query_col = alias
            break

    if not query_col:
        raise ValueError("Dataset must contain a domain query column (e.g., 'query' or 'domain').")

    df['query'] = df[query_col].astype(str)

    # Clean query
    df['query'] = df['query'].str.strip().str.rstrip('.')

    # Timestamp handling
    time_col = None
    for alias in ['timestamp', 'time', 'date', 'datetime']:
        if alias in df.columns:
            time_col = alias
            break

    if time_col:
        df['timestamp'] = pd.to_datetime(df[time_col], errors='coerce')
        # Sort chronologically if timestamps are valid
        if not df['timestamp'].isna().all():
            df = df.sort_values(by='timestamp').reset_index(drop=True)
    else:
        # Generate synthetic chronological timestamps (1 second average step)
        start_time = pd.Timestamp.now()
        df['timestamp'] = [start_time + pd.Timedelta(seconds=i * 1.5) for i in range(len(df))]

    # Calculate Query Length
    if 'query_length' not in df.columns or df['query_length'].isna().any():
        df['query_length'] = df['query'].apply(lambda q: len(str(q)))
    else:
        df['query_length'] = df['query_length'].astype(int)

    # Subdomain extraction
    subdomains = df['query'].apply(extract_subdomain)
    df['subdomain'] = subdomains
    df['subdomain_length'] = subdomains.apply(lambda s: len(str(s)))

    # Calculate Shannon Entropy
    if 'entropy' not in df.columns or df['entropy'].isna().any():
        df['entropy'] = df['query'].apply(shannon_entropy)
    else:
        df['entropy'] = df['entropy'].astype(float).round(4)

    # Subdomain entropy (if subdomain exists, compute its entropy, else query entropy)
    df['subdomain_entropy'] = [
        shannon_entropy(sub) if len(sub) > 0 else shannon_entropy(q)
        for sub, q in zip(df['subdomain'], df['query'])
    ]

    # Digit Ratio
    df['digit_count'] = df['query'].apply(lambda q: sum(c.isdigit() for c in str(q)))
    df['digit_ratio'] = (df['digit_count'] / df['query_length'].replace(0, 1)).round(4)

    # Record Type handling
    rec_col = None
    for alias in ['record_type', 'type', 'qtype', 'query_type']:
        if alias in df.columns:
            rec_col = alias
            break

    if rec_col:
        df['record_type'] = df[rec_col].astype(str).str.upper()
    else:
        df['record_type'] = 'A'

    # Calculate Inter-Arrival Time (IAT)
    if 'inter_arrival_time' not in df.columns or df['inter_arrival_time'].isna().any():
        timestamps = pd.to_datetime(df['timestamp'])
        deltas = timestamps.diff().dt.total_seconds().fillna(0.0)
        # Avoid negative times if out-of-order, set min clamp
        deltas = deltas.apply(lambda x: max(0.001, round(float(x), 4)))
        # For the first element, use median of subsequent deltas if available
        if len(deltas) > 1:
            median_delta = deltas[1:].median()
            deltas.iloc[0] = median_delta if pd.notna(median_delta) and median_delta > 0 else 0.5
        df['inter_arrival_time'] = deltas
    else:
        df['inter_arrival_time'] = df['inter_arrival_time'].astype(float).round(4)

    # Label column handling
    label_col = None
    for alias in ['label', 'class', 'classification', 'is_tunnel', 'suspicious']:
        if alias in df.columns:
            label_col = alias
            break

    if label_col:
        # Standardize labels to 'Normal' or 'Suspicious'
        df['label'] = df[label_col].apply(
            lambda x: 'Suspicious' if str(x).strip().lower() in ['suspicious', 'tunnel', 'tunneling', '1', 'true', 'malicious', 'attack']
            else 'Normal'
        )
    else:
        # If unlabelled, assign heuristic baseline (Entropy > 3.8 and Length > 40 is suspicious)
        df['label'] = df.apply(
            lambda r: 'Suspicious' if (r['entropy'] >= 3.8 and r['query_length'] >= 45) else 'Normal',
            axis=1
        )

    # Format timestamp for JSON presentation
    df['timestamp_str'] = df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')

    return df
