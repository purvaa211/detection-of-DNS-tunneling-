"""
Flask Application for DNS Tunneling Detection using Entropy and Timing Statistics.
Course Project: Probability and Statistics.
"""

import os
import io
import json
import pandas as pd
import numpy as np
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename

import dns_utils
import stats_engine
import detector

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dns-tunneling-stats-secret-key-2026'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'data')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max

# Global state for active dataset
ACTIVE_DATASET_NAME = "sample_dns_traffic.csv"
ACTIVE_DF: pd.DataFrame = None


def load_dataset(filename: str) -> pd.DataFrame:
    """Loads and processes a dataset by filename from the data directory."""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(filepath):
        # Fallback to default
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'sample_dns_traffic.csv')
        filename = 'sample_dns_traffic.csv'

    raw_df = pd.read_csv(filepath)
    processed_df = dns_utils.process_dns_dataframe(raw_df)
    return processed_df


def get_active_df() -> pd.DataFrame:
    global ACTIVE_DF, ACTIVE_DATASET_NAME
    if ACTIVE_DF is None:
        ACTIVE_DF = load_dataset(ACTIVE_DATASET_NAME)
    return ACTIVE_DF


# Initialize default dataset on startup
try:
    ACTIVE_DF = load_dataset(ACTIVE_DATASET_NAME)
except Exception as e:
    print(f"Initial dataset load notice: {e}")


@app.route('/')
def index():
    """Renders the main dashboard."""
    return render_template('index.html', active_dataset=ACTIVE_DATASET_NAME)


# ---------------------------------------------------------------------
# Dataset Management Endpoints
# ---------------------------------------------------------------------

@app.route('/api/dataset/info', methods=['GET'])
def get_dataset_info():
    """Returns metadata and top summary metrics of the active dataset."""
    df = get_active_df()
    total = len(df)
    normal_cnt = int(np.sum(df['label'] == 'Normal'))
    suspicious_cnt = int(np.sum(df['label'] == 'Suspicious'))

    mean_entropy = float(df['entropy'].mean())
    mean_length = float(df['query_length'].mean())
    mean_iat = float(df['inter_arrival_time'].mean())

    available_files = [
        f for f in os.listdir(app.config['UPLOAD_FOLDER'])
        if f.endswith('.csv')
    ]

    return jsonify({
        "status": "success",
        "dataset_name": ACTIVE_DATASET_NAME,
        "total_queries": total,
        "normal_queries": normal_cnt,
        "suspicious_queries": suspicious_cnt,
        "normal_pct": round(normal_cnt / total * 100, 1) if total > 0 else 0,
        "suspicious_pct": round(suspicious_cnt / total * 100, 1) if total > 0 else 0,
        "mean_entropy": round(mean_entropy, 3),
        "mean_length": round(mean_length, 1),
        "mean_iat_seconds": round(mean_iat, 3),
        "available_datasets": available_files
    })


@app.route('/api/dataset/switch', methods=['POST'])
def switch_dataset():
    """Switches the active dataset to another available sample CSV."""
    global ACTIVE_DF, ACTIVE_DATASET_NAME
    data = request.get_json() or {}
    filename = data.get('filename')

    if not filename:
        return jsonify({"status": "error", "message": "Filename is required"}), 400

    filename = secure_filename(filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not os.path.exists(filepath):
        return jsonify({"status": "error", "message": f"Dataset {filename} not found"}), 404

    try:
        ACTIVE_DF = load_dataset(filename)
        ACTIVE_DATASET_NAME = filename
        return jsonify({
            "status": "success",
            "message": f"Switched active dataset to {filename}",
            "dataset_name": filename,
            "rows": len(ACTIVE_DF)
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/dataset/upload', methods=['POST'])
def upload_dataset():
    """Handles custom CSV dataset upload with validation and feature extraction."""
    global ACTIVE_DF, ACTIVE_DATASET_NAME
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file uploaded"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No file selected"}), 400

    if not file.filename.lower().endswith('.csv'):
        return jsonify({"status": "error", "message": "File must be a .csv file"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    try:
        file.save(filepath)
        df_uploaded = load_dataset(filename)
        ACTIVE_DF = df_uploaded
        ACTIVE_DATASET_NAME = filename

        return jsonify({
            "status": "success",
            "message": f"File '{filename}' uploaded and processed successfully.",
            "dataset_name": filename,
            "rows": len(ACTIVE_DF),
            "columns": list(ACTIVE_DF.columns)
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to parse CSV: {str(e)}"}), 400


@app.route('/api/dataset/records', methods=['GET'])
def get_dataset_records():
    """
    Returns paginated, filtered, and searchable records for the data preview table.
    """
    df = get_active_df()

    # Query params
    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 15))
    search = request.args.get('search', '').strip().lower()
    label_filter = request.args.get('label', 'all').strip()
    sort_by = request.args.get('sort_by', 'timestamp')
    sort_order = request.args.get('sort_order', 'asc')

    filtered = df.copy()

    # Label filter
    if label_filter.lower() in ['normal', 'suspicious']:
        filtered = filtered[filtered['label'].str.lower() == label_filter.lower()]

    # Search filter
    if search:
        filtered = filtered[
            filtered['query'].str.lower().str.contains(search, na=False) |
            filtered['record_type'].str.lower().str.contains(search, na=False)
        ]

    # Sorting
    if sort_by in filtered.columns:
        ascending = (sort_order.lower() == 'asc')
        filtered = filtered.sort_values(by=sort_by, ascending=ascending)

    total_records = len(filtered)
    total_pages = max(1, (total_records + page_size - 1) // page_size)
    page = max(1, min(page, total_pages))

    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size

    page_slice = filtered.iloc[start_idx:end_idx]

    records = []
    for _, row in page_slice.iterrows():
        records.append({
            "timestamp": row['timestamp_str'] if 'timestamp_str' in row else str(row['timestamp']),
            "query": str(row['query']),
            "record_type": str(row['record_type']),
            "query_length": int(row['query_length']),
            "entropy": round(float(row['entropy']), 4),
            "inter_arrival_time": round(float(row['inter_arrival_time']), 4),
            "label": str(row['label'])
        })

    return jsonify({
        "status": "success",
        "page": page,
        "page_size": page_size,
        "total_records": total_records,
        "total_pages": total_pages,
        "records": records
    })


@app.route('/api/dataset/download', methods=['GET'])
def download_dataset():
    """Allows downloading the active processed dataset with all calculated statistics."""
    df = get_active_df()
    csv_buffer = io.StringIO()
    df.to_csv(csv_buffer, index=False)
    csv_buffer.seek(0)

    bytes_buffer = io.BytesIO(csv_buffer.getvalue().encode('utf-8'))
    return send_file(
        bytes_buffer,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f"processed_{ACTIVE_DATASET_NAME}"
    )


# ---------------------------------------------------------------------
# Syllabus Concept 1: Descriptive Statistics
# ---------------------------------------------------------------------

@app.route('/api/stats/descriptive', methods=['GET'])
def get_descriptive_stats():
    """
    Computes complete descriptive statistics (mean, median, mode, variance,
    std dev, CV, IQR, skewness, kurtosis), histograms, and box plots.
    """
    df = get_active_df()

    features = ['entropy', 'query_length', 'inter_arrival_time']
    results = {}

    for feat in features:
        overall_stats = stats_engine.compute_descriptive_stats(df[feat])
        normal_stats = stats_engine.compute_descriptive_stats(df[df['label'] == 'Normal'][feat])
        suspicious_stats = stats_engine.compute_descriptive_stats(df[df['label'] == 'Suspicious'][feat])

        # Histograms
        overall_hist = stats_engine.compute_histogram_bins(df[feat], bins=14)
        normal_hist = stats_engine.compute_histogram_bins(df[df['label'] == 'Normal'][feat], bins=14)
        suspicious_hist = stats_engine.compute_histogram_bins(df[df['label'] == 'Suspicious'][feat], bins=14)

        # Boxplot data
        boxplot = stats_engine.compute_boxplot_data(df, feat)

        results[feat] = {
            "descriptive": {
                "overall": overall_stats,
                "normal": normal_stats,
                "suspicious": suspicious_stats
            },
            "histograms": {
                "overall": overall_hist,
                "normal": normal_hist,
                "suspicious": suspicious_hist
            },
            "boxplot": boxplot
        }

    return jsonify({
        "status": "success",
        "features": results
    })


# ---------------------------------------------------------------------
# Syllabus Concept 2: Probability & Distributions
# ---------------------------------------------------------------------

@app.route('/api/stats/probability', methods=['GET', 'POST'])
def get_probability_analysis():
    """
    Computes Bayes' theorem analysis, Binomial batch trials,
    Poisson arrival modeling, and Exponential IAT fits.
    """
    df = get_active_df()

    # Get parameters from query or body
    params = request.get_json() if request.is_json else request.args

    prior = float(params.get('prior_tunnel', 0.05))
    sens = float(params.get('sensitivity', 0.94))
    fpr = float(params.get('fpr', 0.03))

    n_batch = int(params.get('n_batch', 30))
    p_batch = float(params.get('p_batch', 0.15))

    bayes_res = stats_engine.bayes_theorem_analysis(prior, sens, fpr)
    binomial_res = stats_engine.binomial_model(n_batch, p_batch)
    poisson_res = stats_engine.poisson_arrival_model(df, time_bucket_seconds=2.0)
    exponential_res = stats_engine.exponential_iat_model(df)

    return jsonify({
        "status": "success",
        "bayes_theorem": bayes_res,
        "binomial_batch": binomial_res,
        "poisson_process": poisson_res,
        "exponential_iat": exponential_res
    })


# ---------------------------------------------------------------------
# Syllabus Concept 3 & 4: Normal Distribution, Sampling & CLT
# ---------------------------------------------------------------------

@app.route('/api/stats/sampling', methods=['GET', 'POST'])
def get_sampling_and_clt():
    """
    Runs Central Limit Theorem Monte Carlo simulation and computes
    Confidence Intervals (90%, 95%, 99%) and Z-score analysis.
    """
    df = get_active_df()
    params = request.get_json() if request.is_json else request.args

    feature = params.get('feature', 'entropy')
    if feature not in ['entropy', 'query_length', 'inter_arrival_time']:
        feature = 'entropy'

    sample_size_n = int(params.get('sample_size_n', 30))
    num_samples_N = int(params.get('num_samples_N', 500))

    clt_res = stats_engine.central_limit_theorem_simulation(
        df[feature], sample_size_n=sample_size_n, num_samples_N=num_samples_N
    )
    ci_res = stats_engine.compute_confidence_intervals(df[feature])
    zscore_res = stats_engine.z_score_and_normality_analysis(df[feature], feature)

    return jsonify({
        "status": "success",
        "feature": feature,
        "clt_simulation": clt_res,
        "confidence_intervals": ci_res,
        "zscore_and_normality": zscore_res
    })


# ---------------------------------------------------------------------
# Syllabus Concept 5: Hypothesis Testing & ANOVA
# ---------------------------------------------------------------------

@app.route('/api/stats/hypothesis', methods=['GET'])
def get_hypothesis_testing():
    """
    Performs Welch's Two-Sample t-tests, Chi-Square Test of Independence,
    and One-Way ANOVA across record types.
    """
    df = get_active_df()

    normal_df = df[df['label'] == 'Normal']
    suspicious_df = df[df['label'] == 'Suspicious']

    # Two-sample t-tests
    t_test_entropy = stats_engine.two_sample_welch_t_test(
        normal_df['entropy'], suspicious_df['entropy'],
        group1_name="Normal", group2_name="Suspicious", feature_name="Entropy"
    )
    t_test_length = stats_engine.two_sample_welch_t_test(
        normal_df['query_length'], suspicious_df['query_length'],
        group1_name="Normal", group2_name="Suspicious", feature_name="Query Length"
    )
    t_test_iat = stats_engine.two_sample_welch_t_test(
        normal_df['inter_arrival_time'], suspicious_df['inter_arrival_time'],
        group1_name="Normal", group2_name="Suspicious", feature_name="Inter-Arrival Time"
    )

    # Chi-Square Test of Independence (Length Category vs Label)
    chi2_res = stats_engine.chi_square_test_independence(df, cat_col='query_length_cat')

    # One-Way ANOVA (Record Type vs Entropy)
    anova_entropy = stats_engine.one_way_anova(df, group_col='record_type', value_col='entropy')
    anova_length = stats_engine.one_way_anova(df, group_col='record_type', value_col='query_length')

    return jsonify({
        "status": "success",
        "two_sample_t_tests": {
            "entropy": t_test_entropy,
            "query_length": t_test_length,
            "inter_arrival_time": t_test_iat
        },
        "chi_square_test": chi2_res,
        "one_way_anova": {
            "entropy_by_record_type": anova_entropy,
            "length_by_record_type": anova_length
        }
    })


# ---------------------------------------------------------------------
# Syllabus Concept 6: Correlation & Linear Regression
# ---------------------------------------------------------------------

@app.route('/api/stats/regression', methods=['GET'])
def get_correlation_regression():
    """
    Computes Pearson r, Spearman rho, and OLS Linear Regression
    between Query Length and Shannon Entropy.
    """
    df = get_active_df()
    reg_res = stats_engine.correlation_and_regression(df, x_col='query_length', y_col='entropy')
    return jsonify({
        "status": "success",
        "regression": reg_res
    })


# ---------------------------------------------------------------------
# Detection Engine & Threshold Benchmark
# ---------------------------------------------------------------------

@app.route('/api/detector/evaluate', methods=['GET', 'POST'])
def evaluate_detector():
    """
    Evaluates Entropy-Only, Timing-Only, and Combined Statistical Detectors
    using configurable thresholds.
    """
    df = get_active_df()
    params = request.get_json() if request.is_json else request.args

    entropy_thresh = float(params.get('entropy_threshold', 3.75))
    iat_thresh = float(params.get('iat_threshold', 0.30))
    length_thresh = int(params.get('length_threshold', 40))

    benchmark = detector.run_detection_benchmark(
        df,
        entropy_threshold=entropy_thresh,
        iat_threshold=iat_thresh,
        length_threshold=length_thresh
    )

    return jsonify({
        "status": "success",
        "benchmark": benchmark
    })


if __name__ == '__main__':
    # Run development server on port 5000
    app.run(host='0.0.0.0', port=5000, debug=True)
