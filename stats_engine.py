"""
Statistical Engine for Probability and Statistics Course Project.

Implements all syllabus concepts:
1. Descriptive Statistics (mean, median, mode, variance, std dev, CV, IQR, skewness, kurtosis, histograms, boxplots)
2. Probability Models (Bayes' Theorem, Bernoulli, Binomial, Poisson, Exponential)
3. Normal Distribution & Z-Scores (empirical rule, normality tests, outlier detection)
4. Sampling & Central Limit Theorem (CLT simulation, standard error, confidence intervals)
5. Hypothesis Testing (Welch's two-sample t-test, one-sample t-test, Type I/II errors, Chi-Square test, One-Way ANOVA)
6. Correlation & Simple Linear Regression (Pearson r, Spearman rho, OLS slope/intercept, R-squared)
"""

import math
import numpy as np
import pandas as pd
from scipy import stats
from typing import Dict, Any, List, Tuple


def compute_descriptive_stats(series: pd.Series) -> Dict[str, Any]:
    """
    Computes comprehensive descriptive statistics for a numerical pandas Series.
    Handles mean, median, mode, sample & population variance, sample & population std dev,
    standard error, coefficient of variation (CV), IQR, skewness, and kurtosis.
    """
    clean_series = pd.to_numeric(series.dropna(), errors='coerce').dropna()
    n = int(len(clean_series))
    if n == 0:
        return {}

    values = clean_series.values
    mean_val = float(np.mean(values))
    median_val = float(np.median(values))

    # Mode calculation
    mode_res = stats.mode(values, keepdims=True)
    mode_val = float(mode_res.mode[0]) if len(mode_res.mode) > 0 else mean_val

    # Variances and Standard Deviations
    # ddof=1 for sample statistics, ddof=0 for population
    sample_var = float(np.var(values, ddof=1)) if n > 1 else 0.0
    pop_var = float(np.var(values, ddof=0))
    sample_std = float(np.std(values, ddof=1)) if n > 1 else 0.0
    pop_std = float(np.std(values, ddof=0))

    # Standard Error of Mean
    se_mean = sample_std / math.sqrt(n) if n > 0 else 0.0

    # Coefficient of Variation (CV = s / mean * 100)
    cv = (sample_std / mean_val * 100.0) if abs(mean_val) > 1e-9 else 0.0

    # Quartiles & IQR
    q1 = float(np.percentile(values, 25))
    q3 = float(np.percentile(values, 75))
    iqr = q3 - q1
    min_val = float(np.min(values))
    max_val = float(np.max(values))

    # Skewness & Kurtosis
    skew_val = float(stats.skew(values)) if n > 2 else 0.0
    kurt_val = float(stats.kurtosis(values)) if n > 3 else 0.0  # Fisher excess kurtosis

    return {
        "n": n,
        "mean": round(mean_val, 4),
        "median": round(median_val, 4),
        "mode": round(mode_val, 4),
        "sample_variance": round(sample_var, 4),
        "pop_variance": round(pop_var, 4),
        "sample_std": round(sample_std, 4),
        "pop_std": round(pop_std, 4),
        "standard_error": round(se_mean, 4),
        "coefficient_of_variation_pct": round(cv, 2),
        "min": round(min_val, 4),
        "q1": round(q1, 4),
        "q3": round(q3, 4),
        "max": round(max_val, 4),
        "iqr": round(iqr, 4),
        "range": round(max_val - min_val, 4),
        "skewness": round(skew_val, 4),
        "kurtosis": round(kurt_val, 4)
    }


def compute_histogram_bins(series: pd.Series, bins: int = 15) -> Dict[str, Any]:
    """
    Computes histogram bin intervals, frequencies, and midpoints for Chart.js.
    """
    clean_series = pd.to_numeric(series.dropna(), errors='coerce').dropna()
    if len(clean_series) == 0:
        return {"labels": [], "counts": [], "relative_frequencies": []}

    counts, bin_edges = np.histogram(clean_series, bins=bins)
    labels = [f"{bin_edges[i]:.2f}-{bin_edges[i+1]:.2f}" for i in range(len(counts))]
    midpoints = [(bin_edges[i] + bin_edges[i+1]) / 2 for i in range(len(counts))]
    total = len(clean_series)
    rel_freq = [round(c / total, 4) for c in counts]

    return {
        "labels": labels,
        "midpoints": [round(m, 3) for m in midpoints],
        "counts": [int(c) for c in counts],
        "relative_frequencies": rel_freq,
        "bin_edges": [round(float(b), 4) for b in bin_edges]
    }


def compute_boxplot_data(df: pd.DataFrame, feature: str) -> Dict[str, Any]:
    """
    Computes box plot parameters (min, Q1, median, Q3, max, outliers)
    comparing Normal and Suspicious groups for a given feature.
    """
    result = {}
    for group_name in ['Normal', 'Suspicious', 'Overall']:
        if group_name == 'Overall':
            data = pd.to_numeric(df[feature], errors='coerce').dropna().values
        else:
            data = pd.to_numeric(df[df['label'] == group_name][feature], errors='coerce').dropna().values

        if len(data) == 0:
            result[group_name] = {"min": 0, "q1": 0, "median": 0, "q3": 0, "max": 0, "outliers": []}
            continue

        q1 = float(np.percentile(data, 25))
        median = float(np.median(data))
        q3 = float(np.percentile(data, 75))
        iqr = q3 - q1

        lower_whisker = float(max(np.min(data), q1 - 1.5 * iqr))
        upper_whisker = float(min(np.max(data), q3 + 1.5 * iqr))

        outliers = [float(x) for x in data if x < lower_whisker or x > upper_whisker]

        result[group_name] = {
            "min": round(lower_whisker, 4),
            "q1": round(q1, 4),
            "median": round(median, 4),
            "q3": round(q3, 4),
            "max": round(upper_whisker, 4),
            "outliers_count": len(outliers),
            "sample_outliers": [round(x, 4) for x in outliers[:15]]
        }

    return result


# ---------------------------------------------------------
# 2. Probability & Distributions
# ---------------------------------------------------------

def bayes_theorem_analysis(prior_tunnel: float, sensitivity: float, fpr: float) -> Dict[str, Any]:
    """
    Calculates posterior probability using Bayes' Theorem:
        P(Tunnel | Alarm) = [P(Alarm | Tunnel) * P(Tunnel)] / P(Alarm)
    where:
        P(Alarm) = P(Alarm | Tunnel)*P(Tunnel) + P(Alarm | Normal)*P(Normal)
    """
    prior_tunnel = float(np.clip(prior_tunnel, 0.0001, 0.9999))
    prior_normal = 1.0 - prior_tunnel
    sensitivity = float(np.clip(sensitivity, 0.0001, 0.9999))  # P(Alarm | Tunnel)
    fpr = float(np.clip(fpr, 0.0001, 0.9999))                  # P(Alarm | Normal)

    # Law of Total Probability
    p_alarm = (sensitivity * prior_tunnel) + (fpr * prior_normal)

    # Bayes' Theorem
    posterior_tunnel_given_alarm = (sensitivity * prior_tunnel) / p_alarm

    # Negative Predictive Value: P(Normal | No Alarm)
    fnr = 1.0 - sensitivity  # P(No Alarm | Tunnel)
    tnr = 1.0 - fpr          # P(No Alarm | Normal)
    p_no_alarm = (fnr * prior_tunnel) + (tnr * prior_normal)
    posterior_normal_given_no_alarm = (tnr * prior_normal) / p_no_alarm

    base_rate_fallacy_note = (
        f"Notice: Even when sensitivity is {sensitivity*100:.1f}%, if the prior attack base rate is rare ({prior_tunnel*100:.1f}%), "
        f"the probability of a true attack given an alarm is {posterior_tunnel_given_alarm*100:.1f}%. "
        f"This demonstrates the 'Base Rate Fallacy' in probability: false alarms can dominate when legitimate traffic overwhelmingly outnumbers attacks."
    )

    return {
        "prior_tunnel": round(prior_tunnel, 4),
        "prior_normal": round(prior_normal, 4),
        "sensitivity": round(sensitivity, 4),
        "false_positive_rate": round(fpr, 4),
        "marginal_p_alarm": round(p_alarm, 4),
        "posterior_tunnel_given_alarm": round(posterior_tunnel_given_alarm, 4),
        "posterior_pct": round(posterior_tunnel_given_alarm * 100.0, 2),
        "posterior_normal_given_no_alarm": round(posterior_normal_given_no_alarm, 4),
        "base_rate_fallacy_note": base_rate_fallacy_note
    }


def binomial_model(n: int, p: float) -> Dict[str, Any]:
    """
    Calculates Binomial distribution PMF and CDF for observing k tunneling packets
    in a batch of n queries:
        P(X = k) = C(n, k) * p^k * (1 - p)^(n - k)
    """
    n = int(max(1, min(100, n)))
    p = float(np.clip(p, 0.001, 0.999))

    k_values = list(range(0, n + 1))
    pmf = [round(float(stats.binom.pmf(k, n, p)), 5) for k in k_values]
    cdf = [round(float(stats.binom.cdf(k, n, p)), 5) for k in k_values]

    mean = round(float(n * p), 4)
    var = round(float(n * p * (1 - p)), 4)
    std_dev = round(math.sqrt(var), 4)

    return {
        "n": n,
        "p": round(p, 4),
        "mean": mean,
        "variance": var,
        "std_dev": std_dev,
        "k_values": k_values,
        "pmf": pmf,
        "cdf": cdf
    }


def poisson_arrival_model(df: pd.DataFrame, time_bucket_seconds: float = 2.0) -> Dict[str, Any]:
    """
    Models DNS query arrival process as a Poisson Distribution:
        P(K = k) = (lambda^k * exp(-lambda)) / k!
    Counts arrivals per time bucket, estimates lambda, and compares observed vs theoretical counts.
    """
    timestamps = pd.to_datetime(df['timestamp']).sort_values()
    if len(timestamps) < 2:
        return {}

    # Total duration in seconds
    duration = (timestamps.iloc[-1] - timestamps.iloc[0]).total_seconds()
    if duration <= 0:
        duration = len(timestamps) * time_bucket_seconds

    # Group into time buckets
    num_buckets = max(5, int(math.ceil(duration / time_bucket_seconds)))
    bucket_indices = ((timestamps - timestamps.iloc[0]).dt.total_seconds() // time_bucket_seconds).astype(int)
    counts_per_bucket = bucket_indices.value_counts()

    # Reindex to include empty buckets
    all_buckets = pd.Series(0, index=range(num_buckets))
    all_buckets.update(counts_per_bucket)
    observed_arrivals = all_buckets.values

    lambda_est = float(np.mean(observed_arrivals))
    var_est = float(np.var(observed_arrivals, ddof=1)) if len(observed_arrivals) > 1 else lambda_est

    max_k = min(25, int(max(observed_arrivals) + 3))
    k_vals = list(range(0, max_k + 1))

    # Empirical frequencies
    empirical_counts = [int(np.sum(observed_arrivals == k)) for k in k_vals]
    empirical_probs = [round(c / len(observed_arrivals), 4) for c in empirical_counts]

    # Theoretical Poisson PMF
    theoretical_probs = [round(float(stats.poisson.pmf(k, lambda_est)), 4) for k in k_vals]

    # Index of Dispersion (Variance-to-Mean Ratio)
    # Poisson process has VMR ~ 1. VMR > 1 indicates burstiness/clustering (common in attacks).
    vmr = var_est / lambda_est if lambda_est > 0 else 1.0

    dispersion_interpretation = (
        "Traffic is closely Poisson distributed (random independent arrivals)."
        if 0.8 <= vmr <= 1.2 else
        f"Over-dispersed traffic (Variance/Mean = {vmr:.2f} > 1.0). Indicates clustering and automated bursts, characteristic of automated tunneling tools."
    )

    return {
        "time_bucket_seconds": time_bucket_seconds,
        "total_buckets": num_buckets,
        "estimated_lambda": round(lambda_est, 4),
        "sample_variance": round(var_est, 4),
        "dispersion_ratio_vmr": round(vmr, 4),
        "k_vals": k_vals,
        "empirical_frequencies": empirical_probs,
        "theoretical_poisson": theoretical_probs,
        "interpretation": dispersion_interpretation
    }


def exponential_iat_model(df: pd.DataFrame) -> Dict[str, Any]:
    """
    Fits an Exponential distribution f(t) = lambda * exp(-lambda * t)
    to Inter-Arrival Times (IAT) for Normal vs Suspicious traffic.
    In Poisson arrival processes, IATs are exponentially distributed (memoryless property).
    """
    results = {}
    for group in ['Normal', 'Suspicious']:
        sub = df[df['label'] == group]
        iat = pd.to_numeric(sub['inter_arrival_time'], errors='coerce').dropna()
        # Filter small positive IATs
        iat = iat[iat > 0.0001]
        if len(iat) < 5:
            continue

        mean_iat = float(np.mean(iat))
        rate_lambda = 1.0 / mean_iat if mean_iat > 0 else 1.0

        # Create binned distribution
        max_t = min(float(np.percentile(iat, 95)), 5.0)
        t_bins = np.linspace(0.001, max_t, 12)
        counts, _ = np.histogram(iat, bins=t_bins)
        rel_counts = [round(float(c) / len(iat), 4) for c in counts]
        midpoints = [round(float((t_bins[i] + t_bins[i+1]) / 2), 3) for i in range(len(counts))]

        # Theoretical Exponential PDF evaluated at midpoints scaled by bin width
        bin_width = t_bins[1] - t_bins[0]
        theoretical_prob = [
            round(float(stats.expon.pdf(m, scale=mean_iat) * bin_width), 4)
            for m in midpoints
        ]

        results[group] = {
            "mean_iat": round(mean_iat, 4),
            "estimated_lambda": round(rate_lambda, 4),
            "midpoints": midpoints,
            "empirical": rel_counts,
            "theoretical_exponential": theoretical_prob
        }

    return results


# ---------------------------------------------------------
# 3. Normal Distribution & Z-Score Analysis
# ---------------------------------------------------------

def z_score_and_normality_analysis(series: pd.Series, feature_name: str) -> Dict[str, Any]:
    """
    Analyzes Z-scores, the Empirical Rule (68-95-99.7%), and tests for Normality
    (D'Agostino-Pearson omnibus test & Shapiro-Wilk if n <= 5000).
    """
    clean_series = pd.to_numeric(series.dropna(), errors='coerce').dropna()
    n = len(clean_series)
    if n < 5:
        return {}

    values = clean_series.values
    mean_val = float(np.mean(values))
    std_val = float(np.std(values, ddof=1))

    if std_val < 1e-9:
        return {}

    z_scores = (values - mean_val) / std_val

    # Empirical Rule counts
    within_1_sd = np.sum(np.abs(z_scores) <= 1.0) / n * 100.0
    within_2_sd = np.sum(np.abs(z_scores) <= 2.0) / n * 100.0
    within_3_sd = np.sum(np.abs(z_scores) <= 3.0) / n * 100.0

    outliers_3sd = int(np.sum(np.abs(z_scores) > 3.0))

    # Normality Test: D'Agostino-Pearson test
    # tests if kurtosis and skewness match normal distribution
    if n >= 20:
        k2, p_val_dagostino = stats.normaltest(values)
        is_normal_dagostino = bool(p_val_dagostino > 0.05)
    else:
        k2, p_val_dagostino, is_normal_dagostino = 0.0, 1.0, True

    normality_verdict = (
        f"At alpha=0.05, p-value={p_val_dagostino:.4e}. "
        f"{'The distribution does not significantly depart from Normality.' if is_normal_dagostino else 'The distribution departs from Normality (reject H0 of normality).'}"
    )

    return {
        "feature": feature_name,
        "n": n,
        "mean": round(mean_val, 4),
        "std_dev": round(std_val, 4),
        "empirical_rule": {
            "within_1_sigma_pct": round(float(within_1_sd), 2),
            "within_2_sigma_pct": round(float(within_2_sd), 2),
            "within_3_sigma_pct": round(float(within_3_sd), 2),
            "theoretical_target": "68.27% - 95.45% - 99.73%"
        },
        "outliers_count_abs_z_gt_3": outliers_3sd,
        "dagostino_k2_stat": round(float(k2), 4),
        "dagostino_p_value": float(p_val_dagostino),
        "is_normal": is_normal_dagostino,
        "interpretation": normality_verdict
    }


# ---------------------------------------------------------
# 4. Sampling & Central Limit Theorem (CLT)
# ---------------------------------------------------------

def central_limit_theorem_simulation(
    series: pd.Series,
    sample_size_n: int = 30,
    num_samples_N: int = 500
) -> Dict[str, Any]:
    """
    Monte Carlo simulation demonstrating the Central Limit Theorem.
    Repeatedly draws N independent random samples of size n from the dataset,
    computes the sample means, and illustrates that the sampling distribution
    of the sample mean is approximately normal with standard error SE = sigma / sqrt(n).
    """
    clean_series = pd.to_numeric(series.dropna(), errors='coerce').dropna()
    population = clean_series.values
    N_pop = len(population)
    if N_pop < 10:
        return {}

    sample_size_n = int(np.clip(sample_size_n, 2, min(200, N_pop)))
    num_samples_N = int(np.clip(num_samples_N, 50, 2000))

    pop_mean = float(np.mean(population))
    pop_std = float(np.std(population, ddof=0))
    theoretical_se = pop_std / math.sqrt(sample_size_n)

    # Draw N samples of size n (with replacement)
    rng = np.random.default_rng(seed=42)
    sample_matrix = rng.choice(population, size=(num_samples_N, sample_size_n), replace=True)
    sample_means = np.mean(sample_matrix, axis=1)

    mean_of_sample_means = float(np.mean(sample_means))
    empirical_se = float(np.std(sample_means, ddof=1))

    # Histogram of sample means
    counts, bin_edges = np.histogram(sample_means, bins=16)
    labels = [f"{bin_edges[i]:.2f}-{bin_edges[i+1]:.2f}" for i in range(len(counts))]
    midpoints = [(bin_edges[i] + bin_edges[i+1]) / 2 for i in range(len(counts))]
    rel_freq = [round(float(c) / num_samples_N, 4) for c in counts]

    # Theoretical Normal curve coordinates matching theoretical mean and SE
    norm_pdf = [
        round(float(stats.norm.pdf(m, loc=pop_mean, scale=theoretical_se) * (bin_edges[1] - bin_edges[0])), 4)
        for m in midpoints
    ]

    return {
        "sample_size_n": sample_size_n,
        "num_samples_N": num_samples_N,
        "population_mean": round(pop_mean, 4),
        "population_std": round(pop_std, 4),
        "theoretical_standard_error": round(theoretical_se, 4),
        "empirical_mean_of_means": round(mean_of_sample_means, 4),
        "empirical_standard_error": round(empirical_se, 4),
        "clt_histogram": {
            "labels": labels,
            "midpoints": [round(float(m), 3) for m in midpoints],
            "counts": [int(c) for c in counts],
            "relative_frequencies": rel_freq,
            "theoretical_normal_curve": norm_pdf
        },
        "clt_conclusion": (
            f"As n increases to {sample_size_n}, the distribution of sample means converges to a Normal distribution "
            f"centered at mu = {mean_of_sample_means:.4f} (Population mu = {pop_mean:.4f}), "
            f"with empirical SE = {empirical_se:.4f} matching theoretical sigma/sqrt(n) = {theoretical_se:.4f}."
        )
    }


def compute_confidence_intervals(series: pd.Series) -> Dict[str, Any]:
    """
    Computes Confidence Intervals (90%, 95%, 99%) for the population mean
    using the Student's t-distribution:
        mean +- t_(alpha/2, df) * (s / sqrt(n))
    """
    clean_series = pd.to_numeric(series.dropna(), errors='coerce').dropna()
    n = len(clean_series)
    if n < 2:
        return {}

    values = clean_series.values
    mean_val = float(np.mean(values))
    s = float(np.std(values, ddof=1))
    se = s / math.sqrt(n)
    df = n - 1

    ci_results = {}
    for confidence in [0.90, 0.95, 0.99]:
        alpha = 1.0 - confidence
        t_crit = float(stats.t.ppf(1.0 - alpha / 2.0, df=df))
        margin_of_error = t_crit * se
        ci_lower = mean_val - margin_of_error
        ci_upper = mean_val + margin_of_error

        ci_results[f"{int(confidence*100)}%"] = {
            "confidence_level": confidence,
            "t_critical": round(t_crit, 4),
            "margin_of_error": round(margin_of_error, 4),
            "lower_bound": round(ci_lower, 4),
            "upper_bound": round(ci_upper, 4),
            "interpretation": f"We are {int(confidence*100)}% confident that the true population mean lies between {ci_lower:.4f} and {ci_upper:.4f}."
        }

    return {
        "n": n,
        "sample_mean": round(mean_val, 4),
        "sample_std": round(s, 4),
        "standard_error": round(se, 4),
        "degrees_of_freedom": df,
        "confidence_intervals": ci_results
    }


# ---------------------------------------------------------
# 5. Hypothesis Testing & ANOVA
# ---------------------------------------------------------

def two_sample_welch_t_test(
    series1: pd.Series,
    series2: pd.Series,
    group1_name: str = "Normal",
    group2_name: str = "Suspicious",
    feature_name: str = "Entropy"
) -> Dict[str, Any]:
    """
    Welch's Two-Sample t-test (unequal variances assumed):
        H0: mu_1 = mu_2  (Mean feature value is identical in both groups)
        H1: mu_1 != mu_2 (Mean feature value differs significantly between groups)
    Also evaluates Cohen's d effect size and explains Type I and Type II errors.
    """
    g1 = pd.to_numeric(series1.dropna(), errors='coerce').dropna().values
    g2 = pd.to_numeric(series2.dropna(), errors='coerce').dropna().values

    n1, n2 = len(g1), len(g2)
    if n1 < 2 or n2 < 2:
        return {}

    m1, m2 = float(np.mean(g1)), float(np.mean(g2))
    v1, v2 = float(np.var(g1, ddof=1)), float(np.var(g2, ddof=1))
    s1, s2 = math.sqrt(v1), math.sqrt(v2)

    # Welch's t-test
    t_stat, p_val = stats.ttest_ind(g2, g1, equal_var=False)  # testing g2 (Suspicious) vs g1 (Normal)

    # Welch-Satterthwaite degrees of freedom
    num = (v1 / n1 + v2 / n2) ** 2
    den = ((v1 / n1) ** 2) / (n1 - 1) + ((v2 / n2) ** 2) / (n2 - 1)
    df_welch = num / den if den > 0 else (n1 + n2 - 2)

    # Cohen's d effect size (pooled standard deviation)
    s_pooled = math.sqrt(((n1 - 1) * v1 + (n2 - 1) * v2) / (n1 + n2 - 2))
    cohens_d = (m2 - m1) / s_pooled if s_pooled > 1e-9 else 0.0

    # Decision at alpha = 0.05 and 0.01
    reject_h0_alpha_05 = bool(p_val < 0.05)
    reject_h0_alpha_01 = bool(p_val < 0.01)

    conclusion = (
        f"At alpha=0.05, since p-value ({p_val:.4e}) < 0.05, we REJECT H0. "
        f"There is a statistically significant difference in {feature_name} between {group1_name} (mean={m1:.3f}) and {group2_name} (mean={m2:.3f})."
        if reject_h0_alpha_05 else
        f"At alpha=0.05, since p-value ({p_val:.4e}) >= 0.05, we FAIL TO REJECT H0. "
        f"There is insufficient evidence that {feature_name} differs between {group1_name} and {group2_name}."
    )

    type_errors_explanation = {
        "type_I_error": f"Type I error (False Positive, alpha): Concluding that {group2_name} traffic has a different mean {feature_name} when in reality it does not.",
        "type_II_error": f"Type II error (False Negative, beta): Failing to detect a true difference in {feature_name} when tunneling is indeed present.",
        "effect_size": f"Cohen's d = {cohens_d:.3f} ({'Large' if abs(cohens_d) >= 0.8 else 'Medium' if abs(cohens_d) >= 0.5 else 'Small'} effect size)."
    }

    return {
        "feature": feature_name,
        "group1": {"name": group1_name, "n": n1, "mean": round(m1, 4), "std": round(s1, 4)},
        "group2": {"name": group2_name, "n": n2, "mean": round(m2, 4), "std": round(s2, 4)},
        "t_statistic": round(float(t_stat), 4),
        "degrees_of_freedom": round(float(df_welch), 2),
        "p_value": float(p_val),
        "reject_h0_alpha_05": reject_h0_alpha_05,
        "reject_h0_alpha_01": reject_h0_alpha_01,
        "cohens_d": round(cohens_d, 4),
        "conclusion": conclusion,
        "type_errors": type_errors_explanation
    }


def chi_square_test_independence(df: pd.DataFrame, cat_col: str = 'query_length_cat') -> Dict[str, Any]:
    """
    Chi-Square Test of Independence:
        H0: Traffic Label (Normal vs Suspicious) is INDEPENDENT of categorical feature (e.g. Length Category)
        H1: Traffic Label is DEPENDENT on categorical feature.
    """
    df_copy = df.copy()

    # Create categorical bins if query_length_cat not present
    if cat_col == 'query_length_cat' and 'query_length_cat' not in df_copy.columns:
        df_copy['query_length_cat'] = pd.cut(
            df_copy['query_length'],
            bins=[0, 25, 45, 1000],
            labels=['Short (<=25)', 'Medium (26-45)', 'Long (>45)']
        )

    contingency = pd.crosstab(df_copy[cat_col], df_copy['label'])
    if contingency.empty or contingency.shape[0] < 2 or contingency.shape[1] < 2:
        return {}

    chi2_stat, p_val, dof, expected = stats.chi2_contingency(contingency)

    categories = list(contingency.index.astype(str))
    observed_dict = {
        col: [int(v) for v in contingency[col]]
        for col in contingency.columns
    }
    expected_dict = {
        col: [round(float(v), 2) for v in expected[:, idx]]
        for idx, col in enumerate(contingency.columns)
    }

    reject_h0 = bool(p_val < 0.05)
    conclusion = (
        f"Chi-square statistic = {chi2_stat:.4f}, df = {dof}, p-value = {p_val:.4e}. "
        f"{'Reject H0: Query categories and traffic classification are statistically dependent (correlated).' if reject_h0 else 'Fail to reject H0: No statistically significant association found.'}"
    )

    return {
        "cat_column": cat_col,
        "categories": categories,
        "observed": observed_dict,
        "expected": expected_dict,
        "chi2_statistic": round(float(chi2_stat), 4),
        "degrees_of_freedom": int(dof),
        "p_value": float(p_val),
        "reject_h0": reject_h0,
        "conclusion": conclusion
    }


def one_way_anova(df: pd.DataFrame, group_col: str = 'record_type', value_col: str = 'entropy') -> Dict[str, Any]:
    """
    One-Way ANOVA (Analysis of Variance):
        H0: The population mean of value_col is equal across all categories of group_col.
        H1: At least one group mean is significantly different.
    """
    valid_groups = df[group_col].dropna().unique()
    group_data = [
        pd.to_numeric(df[df[group_col] == g][value_col], errors='coerce').dropna().values
        for g in valid_groups
    ]
    # Filter groups with at least 3 observations
    filtered = [(g, data) for g, data in zip(valid_groups, group_data) if len(data) >= 3]

    if len(filtered) < 2:
        return {}

    groups = [item[0] for item in filtered]
    data_arrays = [item[1] for item in filtered]

    f_stat, p_val = stats.f_oneway(*data_arrays)

    group_summaries = []
    total_n = sum(len(arr) for arr in data_arrays)
    grand_mean = sum(np.sum(arr) for arr in data_arrays) / total_n

    # Sum of squares
    ss_between = sum(len(arr) * ((np.mean(arr) - grand_mean) ** 2) for arr in data_arrays)
    ss_within = sum(np.sum((arr - np.mean(arr)) ** 2) for arr in data_arrays)
    ss_total = ss_between + ss_within

    df_between = len(filtered) - 1
    df_within = total_n - len(filtered)

    ms_between = ss_between / df_between if df_between > 0 else 0.0
    ms_within = ss_within / df_within if df_within > 0 else 0.0

    for g, arr in filtered:
        group_summaries.append({
            "group": str(g),
            "n": len(arr),
            "mean": round(float(np.mean(arr)), 4),
            "std": round(float(np.std(arr, ddof=1)), 4)
        })

    reject_h0 = bool(p_val < 0.05)
    conclusion = (
        f"F-statistic = {f_stat:.4f}, p-value = {p_val:.4e}. "
        f"{'Reject H0: Statistically significant difference exists among group means.' if reject_h0 else 'Fail to reject H0: Group means do not differ significantly.'}"
    )

    return {
        "group_col": group_col,
        "value_col": value_col,
        "groups": group_summaries,
        "ss_between": round(float(ss_between), 4),
        "ss_within": round(float(ss_within), 4),
        "ss_total": round(float(ss_total), 4),
        "df_between": df_between,
        "df_within": df_within,
        "ms_between": round(float(ms_between), 4),
        "ms_within": round(float(ms_within), 4),
        "f_statistic": round(float(f_stat), 4),
        "p_value": float(p_val),
        "reject_h0": reject_h0,
        "conclusion": conclusion
    }


# ---------------------------------------------------------
# 6. Correlation & Linear Regression
# ---------------------------------------------------------

def correlation_and_regression(
    df: pd.DataFrame, 
    x_col: str = 'query_length', 
    y_col: str = 'entropy',
    filter_outliers: bool = True
) -> Dict[str, Any]:
    """
    Computes Pearson correlation coefficient r, Spearman rho, and
    Ordinary Least Squares (OLS) simple linear regression:
        y_hat = beta_0 + beta_1 * x
    Removes extreme leverage outliers to yield an accurate, robust linear model.
    """
    clean_df = df[[x_col, y_col]].dropna()
    x_ser = pd.to_numeric(clean_df[x_col], errors='coerce').dropna()
    y_ser = pd.to_numeric(clean_df[y_col], errors='coerce').dropna()
    common_idx = x_ser.index.intersection(y_ser.index)
    x = x_ser.loc[common_idx].values
    y = y_ser.loc[common_idx].values

    n_total = len(x)
    if n_total < 5:
        return {}

    # Outlier filtering on residuals to eliminate extreme leverage points
    n_filtered = 0
    if filter_outliers and n_total >= 15:
        s_init, i_init, _, _, _ = stats.linregress(x, y)
        res = y - (i_init + s_init * x)
        std_res = float(np.std(res))
        if std_res > 1e-6:
            z_res = np.abs(res - np.mean(res)) / std_res
            inlier_mask = z_res <= 2.0
            if np.sum(inlier_mask) >= 10:
                n_filtered = int(n_total - np.sum(inlier_mask))
                x = x[inlier_mask]
                y = y[inlier_mask]

    n = len(x)

    # Pearson & Spearman correlation on accurate, cleaned data
    r_pearson, p_pearson = stats.pearsonr(x, y)
    r_spearman, p_spearman = stats.spearmanr(x, y)

    # Linear Regression (scipy.stats.linregress)
    slope, intercept, r_value, p_value, std_err = stats.linregress(x, y)
    r_squared = r_value ** 2

    # Coordinates for plotting scatter and regression line (subsampled clean points)
    sample_indices = np.random.choice(n, size=min(n, 220), replace=False) if n > 220 else range(n)
    scatter_points = [{"x": round(float(x[i]), 2), "y": round(float(y[i]), 4)} for i in sample_indices]

    x_min, x_max = float(np.min(x)), float(np.max(x))
    line_points = [
        {"x": round(x_min, 2), "y": round(float(intercept + slope * x_min), 4)},
        {"x": round(x_max, 2), "y": round(float(intercept + slope * x_max), 4)}
    ]

    interpretation = (
        f"Pearson r = {r_pearson:.3f} indicates a "
        f"{'strong positive' if r_pearson > 0.6 else 'moderate positive' if r_pearson > 0.3 else 'weak'} linear correlation. "
        f"The regression model explains {r_squared * 100:.1f}% of the variance in {y_col} (R^2 = {r_squared:.4f}). "
        f"Equation: {y_col} = {intercept:.3f} + ({slope:.4f} * {x_col})."
    )

    return {
        "x_col": x_col,
        "y_col": y_col,
        "n_total": n_total,
        "n": n,
        "outliers_removed": n_filtered,
        "pearson_r": round(float(r_pearson), 4),
        "pearson_p_value": float(p_pearson),
        "spearman_rho": round(float(r_spearman), 4),
        "spearman_p_value": float(p_spearman),
        "slope": round(float(slope), 5),
        "intercept": round(float(intercept), 4),
        "r_squared": round(float(r_squared), 4),
        "std_error": round(float(std_err), 5),
        "slope_p_value": float(p_value),
        "regression_line": line_points,
        "scatter_points": scatter_points,
        "interpretation": interpretation
    }
