# Detecting DNS Tunneling Using Entropy and Timing Statistics
### Probability & Mathematical Statistics Course Project

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/backend-Flask-black.svg)](https://flask.palletsprojects.com/)
[![SciPy & NumPy](https://img.shields.io/badge/math-SciPy%20%7C%20NumPy-orange.svg)](https://scipy.org/)
[![Chart.js](https://img.shields.io/badge/frontend-Chart.js-yellow.svg)](https://www.chartjs.org/)
[![License: Academic](https://img.shields.io/badge/license-Academic-green.svg)](LICENSE)

An interactive, rigorous **Probability and Statistics Analysis Platform** built on real-world Domain Name System (DNS) traffic data. This application serves as a comprehensive educational demonstration of syllabus statistics concepts—descriptive statistics, probability distributions, multiple linear regression, hypothesis testing, and statistical anomaly detection—applied to network telemetry without relying on opaque machine learning models.

---

## Table of Contents
1. [Project Overview & Statistical Objectives](#1-project-overview--statistical-objectives)
2. [Technology Stack](#2-technology-stack)
3. [Key Features & Platform Modules (6 Sections)](#3-key-features--platform-modules-6-sections)
4. [Statistical Concepts Implemented](#4-statistical-concepts-implemented)
5. [Directory Structure](#5-directory-structure)
6. [Installation & Setup Instructions](#6-installation--setup-instructions)
7. [Running the Application](#7-running-the-application)
8. [Dataset Formats & Custom CSV Uploads](#8-dataset-formats--custom-csv-uploads)
9. [Automated Test Suite](#9-automated-test-suite)
10. [Academic Integrity & Authors](#10-academic-integrity--authors)

---

## 1. Project Overview & Statistical Objectives

In modern computer networks, Domain Name System (DNS) traffic is primarily used to resolve human-readable domain names into IP addresses. However, attackers can abuse DNS queries to encode arbitrary data (DNS tunneling), bypassing boundary firewalls.

Rather than approaching this solely as a network security problem, this project uses DNS traffic as an empirical telemetry dataset to demonstrate core curriculum topics in **Probability and Mathematical Statistics**:
- Investigating probability distributions governing query rates (Poisson) and inter-arrival times (Exponential).
- Analyzing central tendency, dispersion, skewness, and coefficient of variation between normal and anomalous data.
- Applying OLS Simple & Multiple Linear Regression to examine mathematical relationships between domain attributes.
- Conducting rigorous two-sample hypothesis testing ($t$-test, Welch's test) to assess statistical significance.
- Implementing non-parametric and parametric statistical anomaly detection ($Z$-score and Interquartile Range methods).

---

## 2. Technology Stack

- **Backend:** Python 3.8+, Flask 2.3+ (REST API architecture)
- **Mathematical Computation:** SciPy, NumPy, Pandas
- **Frontend:** Vanilla JavaScript (ES6+), HTML5, CSS3
- **Visualization:** Chart.js 4.4+ (locally hosted bundle for fully offline execution)
- **UI Design Palette:** Warm Ivory (`#F6F4EE`), Deep Plum (`#403747`), Muted Sage (`#667C69`), and Terracotta (`#B77B61`)

---

## 3. Key Features & Platform Modules (6 Sections)

The platform features a fixed sidebar navigation linking six dedicated statistical modules:

### 1. Overview Dashboard
- High-level telemetry cards: Total records analyzed, normal query count, suspicious query count, percentage suspicious, mean query length, mean query frequency, and mean inter-arrival time.
- Traffic distribution breakdown charts (doughnut and comparative bar).
- Key statistical takeaways dynamically computed from active dataset telemetry.
- Paginated, searchable, and filterable DNS traffic records table with real-time category filtering.

### 2. Descriptive Statistics
- Comprehensive statistical parameter tables: Sample size ($n$), Mean ($\bar{x}$), Median ($Q_2$), Mode, Sample Variance ($s^2$), Sample Standard Deviation ($s$), Minimum, Maximum, Range, 1st Quartile ($Q_1$), 3rd Quartile ($Q_3$), Interquartile Range ($IQR$), and Coefficient of Variation ($CV\%$).
- Separate stratified breakdowns for Normal traffic vs. Suspicious traffic.
- Interactive multi-feature selector: Query Length, Subdomain Length, Shannon Entropy, Inter-Arrival Time, and Query Frequency.
- Binned frequency distribution histograms and comparative box plots with statistical interpretation notes.

### 3. Probability & Distributions
- **Empirical Base Rates:** Direct computation of prior probabilities $P(\text{Normal})$ and $P(\text{Suspicious})$.
- **Conditional Probability & Bayes' Theorem:** Mathematical breakdown of detector alarm accuracy and the *Base Rate Fallacy*:
  $$P(\text{Suspicious} \mid \text{Alarm}) = \frac{P(\text{Alarm} \mid \text{Suspicious}) P(\text{Suspicious})}{P(\text{Alarm})}$$
- **Binomial Distribution:** Models the probability of observing $k$ suspicious queries in a random batch of $n$ queries ($X \sim \text{Binomial}(n, p)$) with user-configurable sliders.
- **Normal Distribution & Central Limit Theorem (CLT):** Gaussian theoretical curve fitted against empirical data with dynamic 90%, 95%, and 99% confidence intervals.
- **Poisson Distribution:** Event frequency modeling of queries arriving in configurable time intervals ($\Delta t \in \{1.0s, 2.0s, 5.0s, 10.0s\}$).
- **Exponential Distribution:** Inter-arrival time distribution parameterized by arrival rate $\lambda = 1/\bar{t}$.

### 4. Correlation & Regression
- **Correlation Matrix & Heatmap:** Pairwise Pearson ($r$) and Spearman rank ($\rho$) correlation coefficients calculated across all numerical traffic features.
- **Interactive Feature-Pair Scatter Plot:** Customizable independent ($X$) and dependent ($Y$) variable analysis.
- **Simple Linear Regression:** Ordinary Least Squares (OLS) slope, intercept, regression equation, coefficient of determination ($R^2$), and Mean Squared Error ($MSE$).
- **Residual Analysis Plot:** Scatter of residuals $(y_i - \hat{y}_i)$ against fitted values to evaluate homoscedasticity and linearity.
- **Multiple Linear Regression:** Multi-variable OLS regression equation:
  $$\hat{Y} = \beta_0 + \beta_1 X_1 + \beta_2 X_2 + \dots + \beta_k X_k$$
  Displays individual feature coefficients, standard errors, $t$-statistics, $p$-values, Adjusted $R^2$, and Actual vs. Predicted plots.

### 5. Hypothesis Testing
- **Two-Sample Welch's $t$-Test:** Formal statistical hypothesis testing comparing normal and suspicious traffic parameters without assuming equal population variances:
  $$H_0: \mu_{\text{normal}} = \mu_{\text{suspicious}} \quad \text{vs.} \quad H_1: \mu_{\text{normal}} \neq \mu_{\text{suspicious}}$$
- Outputs degrees of freedom ($df$), $t$-statistic, exact two-tailed $p$-value, Cohen's $d$ effect size, and plain-English null hypothesis verdict.
- **Confidence Intervals:** User-selectable confidence levels (90%, 95%, 99%) for feature means across Normal and Suspicious populations using Student's $t$-distribution.
- **Error Analysis:** Clear explanations of Type I Error (False Positive, $\alpha$) and Type II Error (False Negative, $\beta$).

### 6. Detection Results & Benchmark
- Evaluation of rule-based statistical threshold detectors: Query Length-Only, Inter-Arrival Time-Only, Entropy-Only, and Combined Multi-Criteria.
- Full performance classification metrics: Total Records, True Positives ($TP$), False Positives ($FP$), True Negatives ($TN$), False Negatives ($FN$), Detection Rate / Recall, False Positive Rate ($FPR$), Precision, and $F_1$-Score.
- 2x2 Confusion Matrix visualization.
- Clarification separating statistical rules, detector classifications, and ground truth labels.

---

## 4. Statistical Concepts Implemented

| Concept Category | Specific Methods & Formulas Implemented |
| :--- | :--- |
| **Descriptive Statistics** | Mean, Median, Mode, Variance ($s^2$), Standard Deviation ($s$), IQR, Range, Coefficient of Variation ($CV\%$) |
| **Probability Distributions** | Binomial PMF, Poisson PMF, Exponential PDF, Normal PDF, Empirical Prior Probabilities |
| **Conditional Probability** | Bayes' Theorem, Detector Alarm Posterior, Base Rate Fallacy Analysis |
| **Sampling & CLT** | Standard Error of the Mean ($SE = s/\sqrt{n}$), Confidence Intervals (90%, 95%, 99%) |
| **Hypothesis Testing** | Two-Sample Welch's $t$-test, $p$-values, Degrees of Freedom, Cohen's $d$, Type I/II Errors |
| **Bivariate & Multivariate** | Pearson $r$, Spearman Rank $\rho$, Simple OLS Regression, Multiple Linear Regression, Adjusted $R^2$, Residual Plots |
| **Anomaly Detection** | Standardized $Z$-score filtering, Tukey IQR Boxplot Fences |

---

## 5. Directory Structure

```
detection-of-DNS-tunneling-/
├── app.py                     # Flask REST API backend and application server
├── stats_engine.py            # Core statistical computational library (SciPy, NumPy)
├── detector.py                # Statistical threshold detection and benchmark evaluator
├── dns_utils.py               # DNS feature extractor, frequency counter, and CSV validator
├── generate_data.py           # Synthetic dataset generator for reproducible testing
├── data/                      # Bundled sample datasets
│   ├── sample_dns_traffic.csv             # Baseline mixed enterprise traffic (1,200 records)
│   ├── sample_high_entropy_tunneling.csv  # Tunneling attack surge scenario (700 records)
│   └── sample_normal_workday.csv          # Routine corporate browsing scenario (920 records)
├── templates/
│   └── index.html             # Single-page 6-module dashboard template
├── static/
│   ├── css/
│   │   └── style.css          # Professional Warm Ivory & Deep Plum stylesheet
│   └── js/
│       ├── chart.umd.min.js   # Local, self-contained Chart.js library
│       └── main.js            # Modular frontend application logic and chart rendering
├── tests/
│   ├── test_stats.py          # Unit tests verifying mathematical formulas and edge cases
│   └── test_app.py            # Integration tests for Flask endpoints and file upload validation
├── requirements.txt           # Python dependency specifications
├── .gitignore                 # Git ignore specifications
└── README.md                  # Comprehensive project documentation
```

---

## 6. Installation & Setup Instructions

### Prerequisites
- Python 3.8 or higher installed on your system.
- Git (optional, for version control).

### Step 1: Clone or Navigate to the Repository
```bash
git clone https://github.com/purvaa211/detection-of-DNS-tunneling-.git
cd detection-of-DNS-tunneling-
```

### Step 2: Set Up a Virtual Environment (Recommended)
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Required Dependencies
```bash
pip install -r requirements.txt
```

---

## 7. Running the Application

### Start the Flask Server
```bash
python app.py
```

The server initializes and binds to `http://127.0.0.1:5000/`.

### Open in Browser
Open your web browser and navigate to:
```
http://localhost:5000
```
or
```
http://127.0.0.1:5000
```

---

## 8. Dataset Formats & Custom CSV Uploads

### Bundled Datasets
The application includes three built-in datasets switchable on-the-fly via the top navigation bar:
1. **Mixed Baseline (`sample_dns_traffic.csv`):** Realistic enterprise network traffic with ~15% simulated tunneling queries.
2. **Attack Surge (`sample_high_entropy_tunneling.csv`):** Elevated attack activity with ~40% tunneling queries.
3. **Routine Browsing (`sample_normal_workday.csv`):** Clean everyday browsing traffic with 0% tunneling queries.

### Uploading a Custom CSV
Click the **"Upload CSV"** button in the top navigation bar. Your CSV must meet these requirements:
- **Required Columns:** At least a `query` column containing domain names (e.g., `api.github.com` or `x8f2k9a.tunnel.evil.com`).
- **Optional Columns:**
  - `timestamp`: Date/time format (e.g., `YYYY-MM-DD HH:MM:SS`). If omitted, sequential timestamps are generated automatically.
  - `label`: Categorical label (`Normal` or `Suspicious`). If omitted, baseline heuristics assign provisional reference labels.
- Missing values and malformed rows are sanitized automatically during ingestion.

---

## 9. Automated Test Suite

A comprehensive test suite verifies mathematical accuracy, edge-case resilience, and API stability.

### Run All Tests
```bash
python -m unittest discover tests
```

### Expected Output
```
Ran 31 tests in 0.35s

OK
```

The test suite covers:
- Descriptive statistics formulas (Mean, Median, Sample Variance, SD, CV, IQR).
- Probability distributions (Normal, Poisson, Exponential, Binomial).
- Bayes' Theorem posterior calculations.
- Welch's two-sample $t$-tests and degrees of freedom.
- Correlation matrices and OLS simple/multiple linear regression matrix algebra.
- $Z$-score and IQR anomaly detection algorithms.
- Classification metrics (Precision, Recall, FPR, F1, Confusion Matrix).
- CSV ingestion validation and error handling (empty files, missing required headers).

---

## 10. Academic Integrity & Authors

- **Student Author:** Purva Deshmukh ([@purvaa211](https://github.com/purvaa211))
- **Course:** Probability and Mathematical Statistics Course Project
- **License:** Open Academic Educational Project
