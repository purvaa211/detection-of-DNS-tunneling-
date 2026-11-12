"""
Flask Application for DNS Tunneling Detection using Entropy and Timing Statistics.
Upgraded Probability & Statistics Analytics Platform.
"""

import os
import io
import json
import pandas as pd
import numpy as np
from scipy import stats
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
# 1. Dataset Management Endpoints
# ---------------------------------------------------------------------

@app.route('/api/dataset/info', methods=['GET'])
def get_dataset_info():
    """Returns metadata and top summary metrics of the active dataset."""
    df = get_active_df()
    total = len(df)
    normal_cnt = int(np.sum(df['label'] == 'Normal'))
    suspicious_cnt = int(np.sum(df['label'] == 'Suspicious'))

    mean_entropy = float(df['entropy'].mean()) if 'entropy' in df.columns else 0.0
    mean_length = float(df['query_length'].mean()) if 'query_length' in df.columns else 0.0
    mean_iat = float(df['inter_arrival_time'].mean()) if 'inter_arrival_time' in df.columns else 0.0
    mean_freq = float(df['query_frequency'].mean()) if 'query_frequency' in df.columns else 1.0

    # Quick outlier detection across query_length for summary count
    outlier_res = stats_engine.run_anomaly_detection(df, feature='query_length', z_threshold=2.5)
    total_outliers = outlier_res.get('z_score_method', {}).get('outliers_count', 0)

    available_files = [
        f for f in os.listdir(app.config['UPLOAD_FOLDER'])
        if f.endswith('.csv')
    ]

    is_simulated = ACTIVE_DATASET_NAME.startswith('sample_')
    dataset_desc = "Preloaded simulated educational dataset" if is_simulated else "User uploaded custom dataset"

    # Dynamic observations based on actual data
    obs = []
    normal_len = float(df[df['label'] == 'Normal']['query_length'].mean()) if normal_cnt > 0 else 0.0
    susp_len = float(df[df['label'] == 'Suspicious']['query_length'].mean()) if suspicious_cnt > 0 else 0.0
    if normal_len > 0 and susp_len > 0:
        len_diff_pct = round(((susp_len - normal_len) / normal_len) * 100, 1)
        obs.append(f"Suspicious queries are {len_diff_pct}% longer on average ({susp_len:.1f} vs {normal_len:.1f} characters).")

    normal_iat = float(df[df['label'] == 'Normal']['inter_arrival_time'].mean()) if normal_cnt > 0 else 0.0
    susp_iat = float(df[df['label'] == 'Suspicious']['inter_arrival_time'].mean()) if suspicious_cnt > 0 else 0.0
    if susp_iat < normal_iat:
        obs.append(f"Suspicious traffic exhibits higher arrival frequency with lower mean interval ({susp_iat:.3f}s vs {normal_iat:.3f}s).")
    else:
        obs.append(f"Normal traffic inter-arrival average is {normal_iat:.3f}s; suspicious queries arrive with mean {susp_iat:.3f}s.")

    obs.append(f"{total_outliers} statistical outliers detected beyond 2.5 standard deviations in query length.")

    return jsonify({
        "status": "success",
        "dataset_name": ACTIVE_DATASET_NAME,
        "is_simulated": is_simulated,
        "dataset_description": dataset_desc,
        "total_queries": total,
        "normal_queries": normal_cnt,
        "suspicious_queries": suspicious_cnt,
        "normal_pct": round(normal_cnt / total * 100, 1) if total > 0 else 0,
        "suspicious_pct": round(suspicious_cnt / total * 100, 1) if total > 0 else 0,
        "mean_entropy": round(mean_entropy, 3),
        "mean_length": round(mean_length, 1),
        "mean_iat_seconds": round(mean_iat, 3),
        "mean_frequency": round(mean_freq, 2),
        "total_outliers_detected": total_outliers,
        "observations": obs,
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
            "message": f"Switched to dataset {filename}",
            "dataset_name": filename,
            "total_records": len(ACTIVE_DF)
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to load dataset: {str(e)}"}), 500


@app.route('/api/dataset/upload', methods=['POST'])
def upload_dataset():
    """Handles CSV dataset file uploads with structural validation."""
    global ACTIVE_DF, ACTIVE_DATASET_NAME

    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file part in upload request"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No file selected for upload"}), 400

    if not file.filename.lower().endswith('.csv'):
        return jsonify({"status": "error", "message": "Only CSV files (.csv) are accepted"}), 400

    safe_name = secure_filename(file.filename)
    if not safe_name.startswith('custom_'):
        safe_name = f"custom_{safe_name}"

    save_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)

    try:
        # Read raw uploaded content
        content_stream = io.StringIO(file.stream.read().decode('utf-8', errors='replace'))
        raw_df = pd.read_csv(content_stream)

        # Validate and enrich via dns_utils
        enriched_df = dns_utils.process_dns_dataframe(raw_df)

        # Save validated dataset to disk
        enriched_df.to_csv(save_path, index=False)

        # Set as active
        ACTIVE_DF = enriched_df
        ACTIVE_DATASET_NAME = safe_name

        return jsonify({
            "status": "success",
            "message": f"Successfully validated and loaded {safe_name}",
            "dataset_name": safe_name,
            "total_records": len(enriched_df),
            "columns_detected": list(enriched_df.columns),
            "normal_count": int(np.sum(enriched_df['label'] == 'Normal')),
            "suspicious_count": int(np.sum(enriched_df['label'] == 'Suspicious'))
        })
    except ValueError as ve:
        return jsonify({"status": "error", "message": f"Validation Error: {str(ve)}"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to process CSV file: {str(e)}"}), 500


@app.route('/api/dataset/records', methods=['GET'])
def get_dataset_records():
    """Returns paginated, searchable DNS traffic records."""
    df = get_active_df()

    page = int(request.args.get('page', 1))
    page_size = int(request.args.get('page_size', 12))
    search_query = request.args.get('search', '').strip().lower()
    label_filter = request.args.get('label', 'all').strip()
    sort_by = request.args.get('sort_by', 'timestamp')
    sort_order = request.args.get('sort_order', 'asc')

    filtered_df = df.copy()

    # Search filter
    if search_query:
        filtered_df = filtered_df[filtered_df['query'].astype(str).str.lower().str.contains(search_query)]

    # Label filter
    if label_filter.lower() in ['normal', 'suspicious']:
        filtered_df = filtered_df[filtered_df['label'].str.lower() == label_filter.lower()]

    # Sorting
    if sort_by in filtered_df.columns:
        ascending = (sort_order.lower() == 'asc')
        filtered_df = filtered_df.sort_values(by=sort_by, ascending=ascending)

    total_records = len(filtered_df)
    total_pages = max(1, int(np.ceil(total_records / page_size)))
    page = max(1, min(page, total_pages))

    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    page_slice = filtered_df.iloc[start_idx:end_idx]

    records = []
    for _, row in page_slice.iterrows():
        records.append({
            "timestamp": str(row.get('timestamp', row.get('timestamp_str', ''))),
            "query": str(row['query']),
            "record_type": str(row.get('record_type', 'A')),
            "query_length": int(row['query_length']),
            "entropy": float(round(row['entropy'], 4)) if 'entropy' in row else 0.0,
            "inter_arrival_time": float(round(row['inter_arrival_time'], 4)),
            "query_frequency": float(round(row.get('query_frequency', 1.0), 2)),
            "label": str(row['label'])
        })

    return jsonify({
        "status": "success",
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "total_records": total_records,
        "records": records
    })


@app.route('/api/dataset/download', methods=['GET'])
def download_dataset():
    """Exports the processed active dataset as a CSV file."""
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
# 2. Descriptive Statistics Endpoints
# ---------------------------------------------------------------------

@app.route('/api/stats/descriptive', methods=['GET'])
def get_descriptive_stats():
    """
    Computes comprehensive descriptive statistics, histogram bins,
    and boxplot metrics for all numerical features.
    """
    df = get_active_df()
    features = ['query_length', 'inter_arrival_time', 'entropy', 'query_frequency', 'subdomain_length']

    normal_df = df[df['label'] == 'Normal']
    suspicious_df = df[df['label'] == 'Suspicious']

    results = {}
    for feat in features:
        if feat not in df.columns:
            continue

        desc_normal = stats_engine.compute_descriptive_stats(normal_df[feat])
        desc_suspicious = stats_engine.compute_descriptive_stats(suspicious_df[feat])
        desc_overall = stats_engine.compute_descriptive_stats(df[feat])

        hist_normal = stats_engine.compute_histogram_bins(normal_df[feat], bins=14)
        hist_suspicious = stats_engine.compute_histogram_bins(suspicious_df[feat], bins=14)
        hist_overall = stats_engine.compute_histogram_bins(df[feat], bins=14)

        boxplot_data = stats_engine.compute_boxplot_data(df, feat)

        results[feat] = {
            "descriptive": {
                "normal": desc_normal,
                "suspicious": desc_suspicious,
                "overall": desc_overall
            },
            "histograms": {
                "normal": hist_normal,
                "suspicious": hist_suspicious,
                "overall": hist_overall
            },
            "boxplot": boxplot_data
        }

    return jsonify({
        "status": "success",
        "features": results
    })


# ---------------------------------------------------------------------
# 3. Probability & Distributions Endpoints
# ---------------------------------------------------------------------

@app.route('/api/stats/probability', methods=['GET', 'POST'])
def get_probability_analysis():
    """
    Computes basic probability rates, Bayes' theorem, Binomial batch trials,
    Normal distribution fit, Poisson arrival process, and Exponential IAT model.
    """
    df = get_active_df()
    params = request.get_json() if request.is_json else request.args

    total = len(df)
    norm_cnt = int(np.sum(df['label'] == 'Normal'))
    susp_cnt = int(np.sum(df['label'] == 'Suspicious'))
    p_norm = round(norm_cnt / total, 4) if total > 0 else 0.5
    p_susp = round(susp_cnt / total, 4) if total > 0 else 0.5

    prior = float(params.get('prior_tunnel', p_susp if p_susp > 0 else 0.05))
    sens = float(params.get('sensitivity', 0.94))
    fpr = float(params.get('fpr', 0.03))

    n_batch = int(params.get('n_batch', 30))
    p_batch = float(params.get('p_batch', p_susp if p_susp > 0 else 0.15))

    time_bucket = float(params.get('time_bucket_seconds', 2.0))
    normal_feat = params.get('normal_feature', 'query_length')
    if normal_feat not in df.columns:
        normal_feat = 'query_length'

    bayes_res = stats_engine.bayes_theorem_analysis(prior, sens, fpr)
    binomial_res = stats_engine.binomial_model(n_batch, p_batch)
    poisson_res = stats_engine.poisson_arrival_model(df, time_bucket_seconds=time_bucket)
    exponential_res = stats_engine.exponential_iat_model(df)

    ci_res = stats_engine.compute_confidence_intervals(df[normal_feat])
    zscore_res = stats_engine.z_score_and_normality_analysis(df[normal_feat], normal_feat)

    return jsonify({
        "status": "success",
        "empirical_probs": {
            "p_normal": p_norm,
            "p_suspicious": p_susp,
            "normal_count": norm_cnt,
            "suspicious_count": susp_cnt,
            "total_count": total
        },
        "bayes_theorem": bayes_res,
        "binomial_batch": binomial_res,
        "poisson_process": poisson_res,
        "exponential_iat": exponential_res,
        "normal_fit": {
            "feature": normal_feat,
            "ci_95": ci_res.get('confidence_intervals', {}).get('95%', {}),
            "empirical_rule": zscore_res.get('empirical_rule', {}),
            "mean": zscore_res.get('mean', 0.0),
            "std_dev": zscore_res.get('std_dev', 0.0),
            "normal_curve": zscore_res.get('normal_curve', {}),
            "normality_test": zscore_res.get('normality_test', {}),
            "interpretation": zscore_res.get('interpretation', '')
        }
    })


@app.route('/api/stats/sampling', methods=['GET', 'POST'])
def get_sampling_and_clt():
    """Central Limit Theorem simulation and Confidence Intervals."""
    df = get_active_df()
    params = request.get_json() if request.is_json else request.args

    feature = params.get('feature', 'query_length')
    if feature not in df.columns:
        feature = 'query_length'

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
# 4. Correlation & Regression Endpoints
# ---------------------------------------------------------------------

@app.route('/api/stats/correlation', methods=['GET', 'POST'])
def get_correlation_matrix():
    """
    Computes Pearson and Spearman correlation matrices across numerical features,
    and returns pairwise scatter coordinates for user-selected variable pairs.
    """
    df = get_active_df()
    params = request.get_json() if request.is_json else request.args

    x_col = params.get('x_col', 'query_length')
    y_col = params.get('y_col', 'entropy')

    if x_col not in df.columns:
        x_col = 'query_length'
    if y_col not in df.columns:
        y_col = 'entropy' if 'entropy' in df.columns else 'inter_arrival_time'

    corr_matrix = stats_engine.compute_correlation_matrix(df)

    # Compute two-variable scatter data
    scatter_df = df[[x_col, y_col, 'label']].dropna()
    n = len(scatter_df)
    sample_indices = np.random.choice(n, size=min(n, 250), replace=False) if n > 250 else range(n)

    scatter_normal = []
    scatter_suspicious = []
    for i in sample_indices:
        row = scatter_df.iloc[i]
        pt = {"x": round(float(row[x_col]), 3), "y": round(float(row[y_col]), 3)}
        if row['label'] == 'Suspicious':
            scatter_suspicious.append(pt)
        else:
            scatter_normal.append(pt)

    r_val, p_val = stats.pearsonr(scatter_df[x_col], scatter_df[y_col])
    s_val, _ = stats.spearmanr(scatter_df[x_col], scatter_df[y_col])

    return jsonify({
        "status": "success",
        "matrix": corr_matrix,
        "pair_selected": {
            "x_col": x_col,
            "y_col": y_col,
            "pearson_r": round(float(r_val), 4),
            "pearson_p": float(p_val),
            "spearman_rho": round(float(s_val), 4),
            "scatter_normal": scatter_normal,
            "scatter_suspicious": scatter_suspicious
        }
    })


@app.route('/api/stats/regression', methods=['GET', 'POST'])
def get_correlation_regression():
    """
    Computes Simple Linear Regression (OLS) between selectable X and Y variables,
    calculating slope, intercept, R^2, MSE, residual plot, and scatter points.
    """
    df = get_active_df()
    params = request.get_json() if request.is_json else request.args

    x_col = params.get('x_col', 'query_length')
    y_col = params.get('y_col', 'entropy')

    if x_col not in df.columns:
        x_col = 'query_length'
    if y_col not in df.columns:
        y_col = 'entropy' if 'entropy' in df.columns else 'inter_arrival_time'

    filter_outliers = params.get('filter_outliers', True)
    if isinstance(filter_outliers, str):
        filter_outliers = filter_outliers.lower() in ['true', '1']

    reg_res = stats_engine.correlation_and_regression(
        df, x_col=x_col, y_col=y_col, filter_outliers=filter_outliers
    )

    # Retain pairwise correlations for backwards compatibility
    try:
        clean_subset = df[['query_length', 'entropy', 'inter_arrival_time']].dropna()
        r_len_ent, _ = stats.pearsonr(clean_subset['query_length'], clean_subset['entropy'])
        r_len_iat, _ = stats.pearsonr(clean_subset['query_length'], clean_subset['inter_arrival_time'])
        r_ent_iat, _ = stats.pearsonr(clean_subset['entropy'], clean_subset['inter_arrival_time'])
        reg_res["pairwise_correlations"] = {
            "length_entropy": round(float(r_len_ent), 4),
            "length_iat": round(float(r_len_iat), 4),
            "entropy_iat": round(float(r_ent_iat), 4)
        }
    except Exception:
        reg_res["pairwise_correlations"] = {
            "length_entropy": reg_res.get("pearson_r", 0.0),
            "length_iat": 0.0,
            "entropy_iat": 0.0
        }

    return jsonify({
        "status": "success",
        "regression": reg_res
    })


@app.route('/api/stats/regression/multiple', methods=['GET', 'POST'])
def get_multiple_regression():
    """
    Computes Multiple Linear Regression predicting a dependent variable
    using multiple user-selected independent predictors.
    """
    df = get_active_df()
    params = request.get_json() if request.is_json else request.args

    y_col = params.get('y_col', 'entropy')
    x_cols = params.get('x_cols', ['query_length', 'inter_arrival_time'])

    if isinstance(x_cols, str):
        x_cols = [c.strip() for c in x_cols.split(',') if c.strip()]

    mlr_res = stats_engine.multiple_linear_regression(df, y_col=y_col, x_cols=x_cols)

    return jsonify({
        "status": "success",
        "multiple_regression": mlr_res
    })


# ---------------------------------------------------------------------
# 5. Hypothesis Testing Endpoints
# ---------------------------------------------------------------------

@app.route('/api/stats/hypothesis', methods=['GET', 'POST'])
def get_hypothesis_testing():
    """
    Performs Welch's Two-Sample t-tests comparing Normal vs Suspicious traffic,
    Confidence Interval analysis with configurable confidence levels (90%, 95%, 99%),
    plus Chi-Square Test and ANOVA.
    """
    df = get_active_df()
    params = request.get_json() if request.is_json else request.args

    selected_feat = params.get('feature', 'query_length')
    conf_level = float(params.get('confidence_level', 0.95))
    ci_group = params.get('ci_group', 'Overall')

    normal_df = df[df['label'] == 'Normal']
    suspicious_df = df[df['label'] == 'Suspicious']

    # Two-sample t-tests
    t_tests = {}
    for feat in ['query_length', 'inter_arrival_time', 'entropy', 'query_frequency']:
        if feat in df.columns:
            feat_label = feat.replace('_', ' ').title()
            t_tests[feat] = stats_engine.two_sample_welch_t_test(
                normal_df[feat], suspicious_df[feat],
                group1_name="Normal", group2_name="Suspicious", feature_name=feat_label
            )

    # Confidence interval for selected feature & group
    ci_series = df[selected_feat] if ci_group == 'Overall' else df[df['label'] == ci_group][selected_feat]
    ci_details = stats_engine.compute_confidence_intervals(ci_series, confidence_level=conf_level)

    # Chi-Square Test of Independence
    chi2_res = stats_engine.chi_square_test_independence(df, cat_col='query_length_cat')

    # One-Way ANOVA
    anova_length = stats_engine.one_way_anova(df, group_col='record_type', value_col='query_length')
    anova_entropy = stats_engine.one_way_anova(df, group_col='record_type', value_col='entropy') if 'entropy' in df.columns else {}

    return jsonify({
        "status": "success",
        "two_sample_t_tests": t_tests,
        "selected_feature_test": t_tests.get(selected_feat, {}),
        "confidence_interval_analysis": {
            "feature": selected_feat,
            "group": ci_group,
            "details": ci_details
        },
        "chi_square_test": chi2_res,
        "one_way_anova": {
            "length_by_record_type": anova_length,
            "entropy_by_record_type": anova_entropy
        }
    })


# ---------------------------------------------------------------------
# 6. Statistical Anomaly Detection Endpoints
# ---------------------------------------------------------------------

@app.route('/api/stats/anomaly', methods=['GET', 'POST'])
def get_anomaly_detection():
    """
    Implements statistical outlier detection comparing Z-Score and IQR methods.
    Allows user-adjustable thresholds and returns summary statistics and flagged records.
    """
    df = get_active_df()
    params = request.get_json() if request.is_json else request.args

    feature = params.get('feature', 'query_length')
    if feature not in df.columns:
        feature = 'query_length'

    z_thresh = float(params.get('z_threshold', 2.5))
    iqr_mult = float(params.get('iqr_multiplier', 1.5))

    anomaly_res = stats_engine.run_anomaly_detection(
        df, feature=feature, z_threshold=z_thresh, iqr_multiplier=iqr_mult
    )

    return jsonify({
        "status": "success",
        "anomaly_analysis": anomaly_res
    })


# ---------------------------------------------------------------------
# 7. Detection Results Endpoints
# ---------------------------------------------------------------------

@app.route('/api/detector/evaluate', methods=['GET', 'POST'])
def evaluate_detector():
    """
    Evaluates Length-Only, Entropy-Only, Timing-Only, and Combined Statistical Detectors
    using configurable thresholds, computing complete confusion matrices and diagnostic metrics.
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
