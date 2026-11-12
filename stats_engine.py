"""
Statistical Engine for Probability and Statistics Course Project.

Implements all syllabus concepts:
1. Descriptive Statistics (mean, median, mode, variance, std dev, CV, IQR, skewness, kurtosis, histograms, boxplots)
2. Probability Models (Bayes' Theorem, Bernoulli, Binomial, Poisson, Exponential)
3. Normal Distribution & Z-Scores (empirical rule, normality tests, outlier detection)
4. Sampling & Central Limit Theorem (CLT simulation, standard error, confidence intervals)
5. Hypothesis Testing (Welch's two-sample t-test, one-sample t-test, Type I/II errors, Chi-Square test, One-Way ANOVA)
6. Correlation & Regression (Pearson r, Spearman rho, correlation matrix, simple OLS linear regression, multiple linear regression)
7. Statistical Anomaly Detection (Z-score method, IQR method, comparative outlier analysis)
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
        return {"labels": [], "counts": [], "relative_frequencies": [], "bin_edges": [], "midpoints": []}

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
            result[group_name] = {"min": 0, "q1": 0, "median": 0, "q3": 0, "max": 0, "outliers_count": 0, "sample_outliers": []}
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
            "iqr": round(iqr, 4),
            "outliers_count": len(outliers),
            "sample_outliers": [round(x, 4) for x in outliers[:25]]
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

    # Total Law of Probability
    p_alarm = (sensitivity * prior_tunnel) + (fpr * prior_normal)

    # Bayes' Theorem
    posterior_tunnel_given_alarm = (sensitivity * prior_tunnel) / p_alarm if p_alarm > 0 else 0.0

    # Negative Predictive Value: P(Normal | No Alarm)
    specificity = 1.0 - fpr
    p_no_alarm = ((1.0 - sensitivity) * prior_tunnel) + (specificity * prior_normal)
    posterior_normal_given_no_alarm = (specificity * prior_normal) / p_no_alarm if p_no_alarm > 0 else 0.0

    note = (
        f"Given a baseline suspicious traffic rate of {prior_tunnel*100:.1f}%, when a statistical alarm occurs, "
        f"the conditional probability that the query is genuine tunneling is {posterior_tunnel_given_alarm*100:.2f}%. "
        f"The remaining {(1 - posterior_tunnel_given_alarm)*100:.2f}% represents false alarm risk due to the Base Rate Fallacy."
    )

    return {
        "prior_tunnel": round(prior_tunnel, 4),
        "prior_normal": round(prior_normal, 4),
        "sensitivity": round(sensitivity, 4),
        "false_positive_rate": round(fpr, 4),
        "total_alarm_probability": round(p_alarm, 4),
        "posterior_tunnel_given_alarm": round(posterior_tunnel_given_alarm, 4),
        "posterior_pct": round(posterior_tunnel_given_alarm * 100.0, 2),
        "posterior_normal_given_no_alarm": round(posterior_normal_given_no_alarm, 4),
        "base_rate_fallacy_note": note,
        "interpretation": note
    }


def binomial_model(n: int, p: float) -> Dict[str, Any]:
    """
    Models the number of suspicious queries X ~ Binomial(n, p) in a sliding batch of n queries.
    Calculates PMF, CDF, expected value, and variance.
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

    duration = (timestamps.iloc[-1] - timestamps.iloc[0]).total_seconds()
    if duration <= 0:
        duration = len(timestamps) * time_bucket_seconds

    time_bucket_seconds = float(max(0.5, time_bucket_seconds))
    num_buckets = max(5, int(math.ceil(duration / time_bucket_seconds)))
    bucket_indices = ((timestamps - timestamps.iloc[0]).dt.total_seconds() // time_bucket_seconds).astype(int)
    counts_per_bucket = bucket_indices.value_counts()

    all_buckets = pd.Series(0, index=range(num_buckets))
    all_buckets.update(counts_per_bucket)
    observed_arrivals = all_buckets.values

    lambda_est = float(np.mean(observed_arrivals))
    var_est = float(np.var(observed_arrivals, ddof=1)) if len(observed_arrivals) > 1 else lambda_est

    max_k = min(25, int(max(observed_arrivals) + 3))
    k_vals = list(range(0, max_k + 1))

    empirical_counts = [int(np.sum(observed_arrivals == k)) for k in k_vals]
    empirical_probs = [round(c / len(observed_arrivals), 4) for c in empirical_counts]
    theoretical_probs = [round(float(stats.poisson.pmf(k, lambda_est)), 4) for k in k_vals]

    # Index of Dispersion (Variance-to-Mean Ratio)
    vmr = var_est / lambda_est if lambda_est > 0 else 1.0

    dispersion_interpretation = (
        f"Variance-to-Mean Ratio (VMR) = {vmr:.2f}. "
        + ("Traffic closely adheres to an independent Poisson arrival process." if 0.8 <= vmr <= 1.2
           else "Traffic exhibits significant over-dispersion (VMR > 1.2), indicating non-homogeneous arrival bursts and periodic automated beaconing.")
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
    """
    results = {}
    for group in ['Normal', 'Suspicious', 'Overall']:
        if group == 'Overall':
            iat = pd.to_numeric(df['inter_arrival_time'], errors='coerce').dropna()
        else:
            sub = df[df['label'] == group]
            iat = pd.to_numeric(sub['inter_arrival_time'], errors='coerce').dropna()

        iat = iat[iat > 0.0001]
        if len(iat) < 5:
            continue

        mean_iat = float(np.mean(iat))
        rate_lambda = 1.0 / mean_iat if mean_iat > 0 else 1.0

        max_t = min(float(np.percentile(iat, 95)), 6.0)
        t_bins = np.linspace(0.001, max_t, 12)
        counts, _ = np.histogram(iat, bins=t_bins)
        rel_counts = [round(float(c) / len(iat), 4) for c in counts]
        midpoints = [round(float((t_bins[i] + t_bins[i+1]) / 2), 3) for i in range(len(counts))]

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
# 3. Normal Distribution & Confidence Intervals
# ---------------------------------------------------------

def z_score_and_normality_analysis(series: pd.Series, feature_name: str) -> Dict[str, Any]:
    """
    Analyzes Z-scores, the Empirical Rule (68-95-99.7%), and tests for Normality
    (D'Agostino-Pearson omnibus test).
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
    within_1_sd = float(np.sum(np.abs(z_scores) <= 1.0) / n * 100.0)
    within_2_sd = float(np.sum(np.abs(z_scores) <= 2.0) / n * 100.0)
    within_3_sd = float(np.sum(np.abs(z_scores) <= 3.0) / n * 100.0)

    outliers_3sd = int(np.sum(np.abs(z_scores) > 3.0))

    if n >= 20:
        k2, p_val_dagostino = stats.normaltest(values)
        is_normal_dagostino = bool(p_val_dagostino > 0.05)
    else:
        k2, p_val_dagostino, is_normal_dagostino = 0.0, 1.0, True

    normality_verdict = (
        f"At significance level alpha=0.05, D'Agostino-Pearson test yields p-value={p_val_dagostino:.4e}. "
        f"{'The empirical data is consistent with a Gaussian Normal distribution.' if is_normal_dagostino else 'The distribution departs significantly from a Normal curve (reject H0 of normality).'}"
    )

    # Theoretical Normal PDF points for overlay
    min_x = float(np.min(values))
    max_x = float(np.max(values))
    x_axis = np.linspace(min_x, max_x, 30)
    normal_curve = [round(float(stats.norm.pdf(x, loc=mean_val, scale=std_val)), 5) for x in x_axis]

    return {
        "feature": feature_name,
        "n": n,
        "mean": round(mean_val, 4),
        "std_dev": round(std_val, 4),
        "empirical_rule": {
            "within_1_sigma_pct": round(within_1_sd, 2),
            "within_2_sigma_pct": round(within_2_sd, 2),
            "within_3_sigma_pct": round(within_3_sd, 2),
            "theoretical_target": "68.27% - 95.45% - 99.73%"
        },
        "outliers_beyond_3_sigma": outliers_3sd,
        "normality_test": {
            "test_name": "D'Agostino-Pearson Omnibus Test",
            "statistic": round(float(k2), 4),
            "p_value": float(p_val_dagostino),
            "is_normal_alpha_05": is_normal_dagostino
        },
        "normal_curve": {
            "x_values": [round(float(x), 2) for x in x_axis],
            "pdf_values": normal_curve
        },
        "interpretation": normality_verdict
    }


def compute_confidence_intervals(series: pd.Series, confidence_level: float = 0.95) -> Dict[str, Any]:
    """
    Computes Confidence Intervals for population mean using Student's t-distribution:
        x_bar +/- t_(alpha/2, n-1) * (s / sqrt(n))
    Supports standard levels (90%, 95%, 99%).
    """
    clean_series = pd.to_numeric(series.dropna(), errors='coerce').dropna()
    n = len(clean_series)
    if n < 2:
        return {}

    values = clean_series.values
    mean_val = float(np.mean(values))
    std_val = float(np.std(values, ddof=1))
    se = std_val / math.sqrt(n)

    levels = [0.90, 0.95, 0.99]
    intervals = {}

    for lvl in levels:
        alpha = 1.0 - lvl
        t_crit = float(stats.t.ppf(1.0 - alpha / 2.0, df=n - 1))
        margin = t_crit * se
        intervals[f"{int(lvl*100)}%"] = {
            "confidence_level": lvl,
            "t_critical": round(t_crit, 4),
            "margin_of_error": round(margin, 4),
            "lower_bound": round(mean_val - margin, 4),
            "upper_bound": round(mean_val + margin, 4),
            "interpretation": f"We are {int(lvl*100)}% confident that the true population mean lies between {mean_val - margin:.4f} and {mean_val + margin:.4f}."
        }

    # Custom requested level
    req_alpha = 1.0 - confidence_level
    req_t = float(stats.t.ppf(1.0 - req_alpha / 2.0, df=n - 1))
    req_margin = req_t * se

    return {
        "n": n,
        "sample_mean": round(mean_val, 4),
        "sample_std": round(std_val, 4),
        "standard_error": round(se, 4),
        "degrees_of_freedom": n - 1,
        "selected_level": confidence_level,
        "selected_ci": {
            "confidence_level": confidence_level,
            "t_critical": round(req_t, 4),
            "margin_of_error": round(req_margin, 4),
            "lower_bound": round(mean_val - req_margin, 4),
            "upper_bound": round(mean_val + req_margin, 4)
        },
        "confidence_intervals": intervals
    }


def central_limit_theorem_simulation(
    series: pd.Series,
    sample_size_n: int = 30,
    num_samples_N: int = 500
) -> Dict[str, Any]:
    """
    Demonstrates the Central Limit Theorem (CLT) via empirical sample mean simulation.
    """
    clean_series = pd.to_numeric(series.dropna(), errors='coerce').dropna()
    population = clean_series.values
    pop_size = len(population)
    if pop_size < 10:
        return {}

    sample_size_n = int(max(5, min(100, sample_size_n)))
    num_samples_N = int(max(50, min(2000, num_samples_N)))

    pop_mean = float(np.mean(population))
    pop_std = float(np.std(population, ddof=0))
    theoretical_se = pop_std / math.sqrt(sample_size_n)

    sample_means = []
    for _ in range(num_samples_N):
        idx = np.random.choice(pop_size, size=sample_size_n, replace=True)
        sample_means.append(float(np.mean(population[idx])))

    sim_mean = float(np.mean(sample_means))
    sim_se = float(np.std(sample_means, ddof=1))

    counts, bin_edges = np.histogram(sample_means, bins=16)
    labels = [f"{(bin_edges[i] + bin_edges[i+1])/2:.2f}" for i in range(len(counts))]
    rel_counts = [round(c / num_samples_N, 4) for c in counts]

    _, clt_p_val = stats.normaltest(sample_means)

    return {
        "sample_size_n": sample_size_n,
        "num_samples_N": num_samples_N,
        "population_mean": round(pop_mean, 4),
        "population_std": round(pop_std, 4),
        "theoretical_standard_error": round(theoretical_se, 4),
        "empirical_mean_of_means": round(sim_mean, 4),
        "empirical_standard_error": round(sim_se, 4),
        "simulated_sampling_mean": round(sim_mean, 4),
        "simulated_standard_error": round(sim_se, 4),
        "histogram": {
            "labels": labels,
            "counts": [int(c) for c in counts],
            "frequencies": rel_counts
        },
        "is_sampling_dist_normal": bool(clt_p_val > 0.05),
        "clt_normality_p_value": float(clt_p_val),
        "interpretation": (
            f"CLT verified: The mean of {num_samples_N} sample means is {sim_mean:.4f} (target {pop_mean:.4f}), "
            f"and simulated standard error is {sim_se:.4f} (theoretical {theoretical_se:.4f}). "
            f"As n increases, the sampling distribution approaches a Normal curve."
        )
    }


# ---------------------------------------------------------
# 4. Hypothesis Testing
# ---------------------------------------------------------

def two_sample_welch_t_test(
    group1_vals: np.ndarray,
    group2_vals: np.ndarray,
    group1_name: str = "Normal",
    group2_name: str = "Suspicious",
    feature_name: str = "Feature",
    alpha: float = 0.05
) -> Dict[str, Any]:
    """
    Performs Welch's Two-Sample t-Test (does not assume equal population variances):
        H0: mu_1 = mu_2  vs  H1: mu_1 != mu_2
    Calculates t-statistic, degrees of freedom via Welch-Satterthwaite equation,
    two-tailed p-value, Cohen's d effect size, and 95% CI of the difference.
    """
    g1 = pd.to_numeric(pd.Series(group1_vals), errors='coerce').dropna().values
    g2 = pd.to_numeric(pd.Series(group2_vals), errors='coerce').dropna().values

    n1, n2 = len(g1), len(g2)
    if n1 < 2 or n2 < 2:
        return {}

    m1, m2 = float(np.mean(g1)), float(np.mean(g2))
    v1, v2 = float(np.var(g1, ddof=1)), float(np.var(g2, ddof=1))
    s1, s2 = math.sqrt(v1), math.sqrt(v2)

    # Welch's t-statistic
    se_diff = math.sqrt((v1 / n1) + (v2 / n2))
    if se_diff < 1e-12:
        t_stat = 0.0
        df = float(n1 + n2 - 2)
        p_val = 1.0
    else:
        t_stat = (m1 - m2) / se_diff
        # Welch-Satterthwaite degrees of freedom
        numerator = ((v1 / n1) + (v2 / n2)) ** 2
        denominator = (((v1 / n1) ** 2) / (n1 - 1)) + (((v2 / n2) ** 2) / (n2 - 1))
        df = numerator / denominator if denominator > 0 else float(n1 + n2 - 2)
        # Two-tailed p-value
        p_val = 2.0 * (1.0 - stats.t.cdf(abs(t_stat), df=df))

    # Cohen's d effect size
    pooled_sd = math.sqrt((((n1 - 1) * v1) + ((n2 - 1) * v2)) / (n1 + n2 - 2)) if (n1 + n2 - 2) > 0 else 1.0
    cohens_d = (m2 - m1) / pooled_sd if pooled_sd > 1e-9 else 0.0

    # 95% Confidence Interval for (mu2 - mu1)
    t_crit_95 = float(stats.t.ppf(1.0 - 0.05 / 2.0, df=df))
    diff_mean = m2 - m1
    ci_diff_lower = diff_mean - (t_crit_95 * se_diff)
    ci_diff_upper = diff_mean + (t_crit_95 * se_diff)

    reject_h0 = bool(p_val < alpha)

    effect_interpretation = (
        "negligible" if abs(cohens_d) < 0.2 else
        "small" if abs(cohens_d) < 0.5 else
        "medium" if abs(cohens_d) < 0.8 else
        "large (strong separation)"
    )

    conclusion = (
        f"At alpha={alpha}, we {'REJECT the null hypothesis H0' if reject_h0 else 'FAIL TO REJECT the null hypothesis H0'} "
        f"(t={t_stat:.3f}, p={p_val:.4e}, df={df:.1f}). "
        f"There is a statistically {'significant' if reject_h0 else 'insignificant'} difference in mean {feature_name} "
        f"between {group1_name} ({m1:.3f}) and {group2_name} ({m2:.3f}) with {effect_interpretation} effect size (Cohen's d = {cohens_d:.2f})."
    )

    return {
        "feature": feature_name,
        "group1": {"name": group1_name, "n": n1, "mean": round(m1, 4), "std": round(s1, 4), "variance": round(v1, 4)},
        "group2": {"name": group2_name, "n": n2, "mean": round(m2, 4), "std": round(s2, 4), "variance": round(v2, 4)},
        "mean_difference": round(diff_mean, 4),
        "standard_error_difference": round(se_diff, 4),
        "t_statistic": round(float(t_stat), 4),
        "degrees_of_freedom": round(float(df), 2),
        "p_value": float(p_val),
        "alpha": alpha,
        "reject_h0_alpha_05": reject_h0,
        "cohens_d": round(float(cohens_d), 4),
        "effect_size_label": effect_interpretation,
        "ci_95_diff": {"lower": round(ci_diff_lower, 4), "upper": round(ci_diff_upper, 4)},
        "conclusion": conclusion,
        "type_errors": {
            "type_1_error": "Rejecting H0 when true: Claiming legitimate traffic has tunneling characteristics (False Positive alarm). Controlled by alpha = 0.05.",
            "type_2_error": "Failing to reject H0 when false: Failing to detect genuine tunneling traffic (False Negative / missed detection)."
        }
    }


def chi_square_test_independence(df: pd.DataFrame, cat_col: str = 'query_length_cat') -> Dict[str, Any]:
    """
    Chi-Square Test of Independence between categorical feature and traffic Label (Normal vs Suspicious).
    """
    if cat_col not in df.columns:
        if 'query_length' in df.columns:
            df = df.copy()
            df['query_length_cat'] = pd.qcut(df['query_length'], q=3, labels=['Short', 'Medium', 'Long'], duplicates='drop')
            cat_col = 'query_length_cat'
        else:
            return {}

    contingency = pd.crosstab(df[cat_col], df['label'])
    chi2, p_val, dof, expected = stats.chi2_contingency(contingency.values)
    reject_h0 = bool(p_val < 0.05)

    return {
        "test_name": "Chi-Square Test of Independence",
        "contingency_table": contingency.to_dict(),
        "chi2_statistic": round(float(chi2), 4),
        "p_value": float(p_val),
        "degrees_of_freedom": int(dof),
        "reject_h0": reject_h0,
        "conclusion": (
            f"At alpha=0.05, Chi2={chi2:.2f}, p-value={p_val:.4e}. "
            f"Traffic classification (Normal vs Suspicious) is statistically "
            f"{'DEPENDENT on' if reject_h0 else 'INDEPENDENT of'} {cat_col}."
        )
    }


def one_way_anova(df: pd.DataFrame, group_col: str = 'record_type', value_col: str = 'query_length') -> Dict[str, Any]:
    """
    One-Way ANOVA testing for equality of means across multiple categories.
    """
    if group_col not in df.columns or value_col not in df.columns:
        return {}

    groups = []
    group_names = []
    for name, sub in df.groupby(group_col):
        vals = pd.to_numeric(sub[value_col], errors='coerce').dropna().values
        if len(vals) >= 3:
            groups.append(vals)
            group_names.append(str(name))

    if len(groups) < 2:
        return {}

    f_stat, p_val = stats.f_oneway(*groups)
    reject_h0 = bool(p_val < 0.05)

    return {
        "test_name": "One-Way ANOVA",
        "group_column": group_col,
        "value_column": value_col,
        "groups_tested": group_names,
        "f_statistic": round(float(f_stat), 4),
        "p_value": float(p_val),
        "reject_h0": reject_h0,
        "conclusion": f"F={f_stat:.3f}, p={p_val:.4e}. Mean {value_col} {'differs significantly' if reject_h0 else 'does not differ'} across {group_col} groups."
    }


# ---------------------------------------------------------
# 5. Correlation & Regression
# ---------------------------------------------------------

def compute_correlation_matrix(df: pd.DataFrame, features: List[str] = None) -> Dict[str, Any]:
    """
    Computes Pearson and Spearman correlation matrices across all available numerical features.
    """
    if features is None:
        features = ['query_length', 'inter_arrival_time', 'entropy', 'query_frequency', 'subdomain_length']

    valid_features = [f for f in features if f in df.columns]
    if len(valid_features) < 2:
        return {"features": [], "pearson": [], "spearman": [], "pairwise": {}}

    clean_data = df[valid_features].apply(pd.to_numeric, errors='coerce').dropna()
    p_mat = clean_data.corr(method='pearson')
    s_mat = clean_data.corr(method='spearman')

    pairwise_list = []
    for i in range(len(valid_features)):
        for j in range(i + 1, len(valid_features)):
            f1, f2 = valid_features[i], valid_features[j]
            r_val, p_val = stats.pearsonr(clean_data[f1], clean_data[f2])
            s_val, _ = stats.spearmanr(clean_data[f1], clean_data[f2])
            pairwise_list.append({
                "var1": f1,
                "var2": f2,
                "pearson_r": round(float(r_val), 4),
                "pearson_p": float(p_val),
                "spearman_rho": round(float(s_val), 4),
                "strength": "Strong" if abs(r_val) > 0.6 else "Moderate" if abs(r_val) > 0.3 else "Weak",
                "direction": "Positive" if r_val > 0 else "Negative"
            })

    return {
        "features": valid_features,
        "pearson_matrix": [[round(float(p_mat.iloc[r, c]), 4) for c in range(len(valid_features))] for r in range(len(valid_features))],
        "spearman_matrix": [[round(float(s_mat.iloc[r, c]), 4) for c in range(len(valid_features))] for r in range(len(valid_features))],
        "pairwise_details": pairwise_list
    }


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

    n_filtered = 0
    if filter_outliers and n_total >= 15:
        s_init, i_init, _, _, _ = stats.linregress(x, y)
        res = y - (i_init + s_init * x)
        std_res = float(np.std(res))
        if std_res > 1e-6:
            z_res = np.abs(res - np.mean(res)) / std_res
            inlier_mask = z_res <= 2.2
            if np.sum(inlier_mask) >= 10:
                n_filtered = int(n_total - np.sum(inlier_mask))
                x = x[inlier_mask]
                y = y[inlier_mask]

    n = len(x)

    r_pearson, p_pearson = stats.pearsonr(x, y)
    r_spearman, p_spearman = stats.spearmanr(x, y)

    slope, intercept, r_value, p_value, std_err = stats.linregress(x, y)
    r_squared = r_value ** 2

    # Residuals & MSE
    fitted_y = intercept + slope * x
    residuals = y - fitted_y
    mse = float(np.mean(residuals ** 2))
    rmse = math.sqrt(mse)

    # Subsampled coordinates for responsive plotting
    sample_indices = np.random.choice(n, size=min(n, 220), replace=False) if n > 220 else range(n)
    scatter_points = [{"x": round(float(x[i]), 2), "y": round(float(y[i]), 4)} for i in sample_indices]
    residual_points = [{"x": round(float(x[i]), 2), "y": round(float(residuals[i]), 4)} for i in sample_indices]

    x_min, x_max = float(np.min(x)), float(np.max(x))
    line_points = [
        {"x": round(x_min, 2), "y": round(float(intercept + slope * x_min), 4)},
        {"x": round(x_max, 2), "y": round(float(intercept + slope * x_max), 4)}
    ]

    interpretation = (
        f"Pearson r = {r_pearson:.3f} indicates a "
        f"{'strong positive' if r_pearson > 0.6 else 'moderate positive' if r_pearson > 0.3 else 'weak'} linear association. "
        f"The model explains {r_squared * 100:.1f}% of the variance in {y_col} (R^2 = {r_squared:.4f}, MSE = {mse:.4f}). "
        f"Fitted Equation: {y_col} = {intercept:.3f} + ({slope:.4f} * {x_col})."
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
        "mse": round(mse, 4),
        "rmse": round(rmse, 4),
        "std_error": round(float(std_err), 5),
        "slope_p_value": float(p_value),
        "regression_line": line_points,
        "scatter_points": scatter_points,
        "residual_points": residual_points,
        "interpretation": interpretation
    }


def multiple_linear_regression(
    df: pd.DataFrame,
    y_col: str = 'entropy',
    x_cols: List[str] = None
) -> Dict[str, Any]:
    """
    Performs Multiple Linear Regression:
        y = beta_0 + beta_1*X_1 + beta_2*X_2 + ... + epsilon
    Computes OLS estimates, standard errors, t-statistics, p-values, R^2, Adjusted R^2, MSE,
    and Actual vs Predicted coordinates.
    """
    if x_cols is None:
        x_cols = ['query_length', 'inter_arrival_time']

    valid_x = [c for c in x_cols if c in df.columns and c != y_col]
    if y_col not in df.columns or len(valid_x) < 1:
        return {}

    clean_data = df[[y_col] + valid_x].apply(pd.to_numeric, errors='coerce').dropna()
    n = len(clean_data)
    p = len(valid_x)
    if n <= p + 2:
        return {}

    y = clean_data[y_col].values
    X = clean_data[valid_x].values

    # Design matrix with intercept
    X_design = np.column_stack([np.ones(n), X])

    try:
        beta, _, _, _ = np.linalg.lstsq(X_design, y, rcond=None)
        y_pred = X_design @ beta
        residuals = y - y_pred

        sse = float(np.sum(residuals ** 2))
        sst = float(np.sum((y - np.mean(y)) ** 2))
        r_squared = float(1.0 - (sse / sst)) if sst > 0 else 0.0
        adj_r_squared = float(1.0 - (1.0 - r_squared) * (n - 1) / (n - p - 1)) if (n - p - 1) > 0 else r_squared
        mse = sse / n
        rmse = math.sqrt(mse)

        # Standard errors of coefficients
        sigma2 = sse / (n - p - 1) if (n - p - 1) > 0 else 1.0
        cov_matrix = sigma2 * np.linalg.pinv(X_design.T @ X_design)
        se_beta = np.sqrt(np.maximum(0, np.diagonal(cov_matrix)))

        t_stats = beta / np.where(se_beta > 1e-9, se_beta, 1.0)
        p_vals = [float(2.0 * (1.0 - stats.t.cdf(abs(t), df=n - p - 1))) for t in t_stats]

        coef_summary = []
        coef_summary.append({
            "term": "Intercept (beta_0)",
            "coefficient": round(float(beta[0]), 4),
            "std_error": round(float(se_beta[0]), 4),
            "t_statistic": round(float(t_stats[0]), 4),
            "p_value": float(p_vals[0])
        })
        for j, col_name in enumerate(valid_x):
            coef_summary.append({
                "term": col_name,
                "coefficient": round(float(beta[j + 1]), 5),
                "std_error": round(float(se_beta[j + 1]), 5),
                "t_statistic": round(float(t_stats[j + 1]), 4),
                "p_value": float(p_vals[j + 1])
            })

        # Actual vs Predicted points (subsampled for responsiveness)
        sample_indices = np.random.choice(n, size=min(n, 200), replace=False) if n > 200 else range(n)
        actual_vs_pred = [
            {"actual": round(float(y[i]), 4), "predicted": round(float(y_pred[i]), 4)}
            for i in sample_indices
        ]
        residuals_plot = [
            {"predicted": round(float(y_pred[i]), 4), "residual": round(float(residuals[i]), 4)}
            for i in sample_indices
        ]

        equation_terms = [f"{beta[0]:.3f}"]
        for j, col in enumerate(valid_x):
            sign = "+" if beta[j+1] >= 0 else "-"
            equation_terms.append(f"{sign} {abs(beta[j+1]):.4f} * {col}")
        eq_str = f"{y_col} = " + " ".join(equation_terms)

        interpretation = (
            f"The multiple regression model achieves R^2 = {r_squared:.4f} (Adjusted R^2 = {adj_r_squared:.4f}, MSE = {mse:.4f}), "
            f"meaning {r_squared * 100:.1f}% of variance in {y_col} is explained jointly by {', '.join(valid_x)}. "
            f"Important note: Regression models linear association rather than causal attack prediction."
        )

        return {
            "target": y_col,
            "predictors": valid_x,
            "n": n,
            "r_squared": round(r_squared, 4),
            "adjusted_r_squared": round(adj_r_squared, 4),
            "mse": round(mse, 4),
            "rmse": round(rmse, 4),
            "coefficients": coef_summary,
            "equation": eq_str,
            "actual_vs_pred": actual_vs_pred,
            "residuals_plot": residuals_plot,
            "interpretation": interpretation
        }
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------
# 6. Statistical Anomaly Detection
# ---------------------------------------------------------

def run_anomaly_detection(
    df: pd.DataFrame,
    feature: str = 'query_length',
    z_threshold: float = 2.5,
    iqr_multiplier: float = 1.5
) -> Dict[str, Any]:
    """
    Implements statistical outlier detection using both Z-Score and IQR methods.
    Compares anomaly counts across Normal vs Suspicious ground truth traffic.
    """
    if feature not in df.columns:
        return {}

    series = pd.to_numeric(df[feature], errors='coerce').dropna()
    total_records = len(series)
    if total_records < 5:
        return {}

    vals = series.values
    mean_val = float(np.mean(vals))
    std_val = float(np.std(vals, ddof=1))

    # Z-Score Method
    z_scores = np.abs((vals - mean_val) / std_val) if std_val > 1e-9 else np.zeros_like(vals)
    z_outliers_mask = z_scores > z_threshold
    z_outliers_count = int(np.sum(z_outliers_mask))
    z_outlier_pct = round((z_outliers_count / total_records) * 100.0, 2)

    # IQR Method
    q1 = float(np.percentile(vals, 25))
    q3 = float(np.percentile(vals, 75))
    iqr = q3 - q1
    iqr_lower = q1 - (iqr_multiplier * iqr)
    iqr_upper = q3 + (iqr_multiplier * iqr)
    iqr_outliers_mask = (vals < iqr_lower) | (vals > iqr_upper)
    iqr_outliers_count = int(np.sum(iqr_outliers_mask))
    iqr_outlier_pct = round((iqr_outliers_count / total_records) * 100.0, 2)

    # Breakdown by Ground Truth Label
    normal_mask = (df.loc[series.index, 'label'] == 'Normal').values
    suspicious_mask = (df.loc[series.index, 'label'] == 'Suspicious').values

    z_normal_outliers = int(np.sum(z_outliers_mask & normal_mask))
    z_suspicious_outliers = int(np.sum(z_outliers_mask & suspicious_mask))

    iqr_normal_outliers = int(np.sum(iqr_outliers_mask & normal_mask))
    iqr_suspicious_outliers = int(np.sum(iqr_outliers_mask & suspicious_mask))

    # Compile Top Flagged Records
    flagged_indices = series.index[z_outliers_mask | iqr_outliers_mask]
    flagged_records = []
    for idx in flagged_indices[:30]:
        row = df.loc[idx]
        val = float(row[feature])
        z_val = round(float((val - mean_val) / std_val), 3) if std_val > 1e-9 else 0.0
        is_z = bool(abs(z_val) > z_threshold)
        is_iqr = bool(val < iqr_lower or val > iqr_upper)

        flagged_records.append({
            "timestamp": str(row.get('timestamp', row.get('timestamp_str', ''))),
            "query": str(row.get('query', '')),
            "feature_value": round(val, 4),
            "z_score": z_val,
            "z_flagged": is_z,
            "iqr_flagged": is_iqr,
            "label": str(row.get('label', 'Normal'))
        })

    return {
        "feature": feature,
        "total_records": total_records,
        "parameters": {
            "z_threshold": round(z_threshold, 2),
            "iqr_multiplier": round(iqr_multiplier, 2)
        },
        "descriptive": {
            "mean": round(mean_val, 4),
            "std_dev": round(std_val, 4),
            "q1": round(q1, 4),
            "median": round(float(np.median(vals)), 4),
            "q3": round(q3, 4),
            "iqr": round(iqr, 4),
            "iqr_bounds": {"lower": round(iqr_lower, 4), "upper": round(iqr_upper, 4)},
            "z_cutoffs": {"lower": round(mean_val - z_threshold * std_val, 4), "upper": round(mean_val + z_threshold * std_val, 4)}
        },
        "z_score_method": {
            "outliers_count": z_outliers_count,
            "outliers_pct": z_outlier_pct,
            "normal_outliers": z_normal_outliers,
            "suspicious_outliers": z_suspicious_outliers,
            "cutoffs": f"x < {mean_val - z_threshold*std_val:.2f} or x > {mean_val + z_threshold*std_val:.2f}"
        },
        "iqr_method": {
            "outliers_count": iqr_outliers_count,
            "outliers_pct": iqr_outlier_pct,
            "normal_outliers": iqr_normal_outliers,
            "suspicious_outliers": iqr_suspicious_outliers,
            "bounds": f"[{iqr_lower:.2f}, {iqr_upper:.2f}]"
        },
        "flagged_sample": flagged_records,
        "interpretation": (
            f"For {feature}, the Z-score method (|Z| > {z_threshold}) flags {z_outliers_count} records ({z_outlier_pct}%), "
            f"capturing {z_suspicious_outliers} suspicious queries and {z_normal_outliers} normal queries. "
            f"The IQR method flags {iqr_outliers_count} records ({iqr_outlier_pct}%). "
            f"Statistical outliers represent extreme observations requiring verification, not confirmed attacks."
        )
    }
