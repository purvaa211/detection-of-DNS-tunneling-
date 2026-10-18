# Detecting DNS Tunneling Using Entropy and Timing Statistics

**Course Project:** Probability and Statistics (MATH / Computer Science Curriculum)  
**Demonstration Web Application:** Python Flask, SciPy, NumPy, and Chart.js  

---

## 1. Project Overview & Academic Abstract

DNS Tunneling is a covert channel technique where attackers encode unauthorized data (such as stolen credentials, command-and-control payloads, or VPN traffic) inside domain name queries (e.g., `dnscat.a7f9b0c1e8...tunnel.attacker.com`) to bypass firewalls and exfiltrate information.

Rather than relying on complex cybersecurity tools or rigid signatures, this project approaches the problem strictly through the lens of **Probability and Mathematical Statistics**. We analyze two primary continuous random variables extracted from network traffic:
1. **Shannon Entropy ($H$):** Measures the average informational randomness of domain characters in bits per character. Natural language domains exhibit lower entropy ($\sim 2.0 - 3.4$ bits/char), whereas encrypted/encoded tunneling payloads exhibit significantly higher entropy ($\sim 4.0 - 4.9$ bits/char).
2. **Inter-Arrival Time ($\Delta t$):** Measures the time interval between successive queries. Normal human browsing approximates a memoryless Poisson arrival process with exponential inter-arrival times, whereas automated exfiltration tools generate rapid bursts or periodic beaconing that violate exponential memorylessness.

The project features a **complete, interactive, student-developed web application** that applies the entire syllabus curriculum to real-world and simulated DNS traffic data.

---

## 2. Probability and Statistics Syllabus Coverage

Every syllabus concept is fully implemented in the code, visualized in the interactive web interface, and explained in clear statistical language:

| Syllabus Concept | Mathematical Formulation | Practical Application in Project |
| :--- | :--- | :--- |
| **Descriptive Statistics** | $\bar{x} = \frac{\sum x_i}{n}$, $s^2 = \frac{\sum (x_i - \bar{x})^2}{n-1}$, $CV = \frac{s}{\bar{x}}\times 100\%$ | Computes mean, median, mode, sample & population variance, standard deviation, standard error, coefficient of variation ($CV$), quartiles ($Q_1, Q_3$), and interquartile range ($IQR$) for normal vs suspicious traffic. |
| **Frequency Distributions** | $f_i = \text{count}(x \in \text{bin}_i)$, $p_i = \frac{f_i}{N}$ | Binned frequency distribution histograms and comparative box-and-whisker plots identifying distribution shapes and outliers. |
| **Conditional Probability & Bayes' Theorem** | $P(T \mid A) = \frac{P(A \mid T) P(T)}{P(A \mid T) P(T) + P(A \mid \neg T) P(\neg T)}$ | Interactive Bayes' Theorem calculator demonstrating the **Base Rate Fallacy**: why even a 95% sensitive detector produces false alarms if the prior attack base rate $P(T)$ is rare. |
| **Binomial Distribution** | $P(X=k) = \binom{n}{k} p^k (1-p)^{n-k}$, $E[X]=np$ | Models the probability of encountering $k$ malicious tunneling packets in a sliding batch of $n$ queries, plotting both PMF and CDF. |
| **Poisson Arrival Process** | $P(K=k) = \frac{\lambda^k e^{-\lambda}}{k!}$, $\text{VMR} = \frac{\sigma^2}{\mu}$ | Estimates query arrival rate $\lambda$ per time window and calculates the Index of Dispersion (Variance-to-Mean Ratio) to detect automated query clustering ($\text{VMR} > 1$). |
| **Exponential Distribution** | $f(t) = \lambda e^{-\lambda t}$, $E[T] = \frac{1}{\lambda}$ | Models memoryless inter-arrival times for benign traffic and highlights departures caused by automated periodic beaconing. |
| **Normal Distribution & Z-Scores** | $Z = \frac{X - \mu}{\sigma}$, Empirical Rule ($68\% - 95\% - 99.7\%$) | Evaluates standard scores, checks theoretical tail probabilities, and tests for normality departures using the D'Agostino-Pearson omnibus test. |
| **Sampling & Central Limit Theorem (CLT)** | $\bar{X}_n \xrightarrow{d} \mathcal{N}\left(\mu, \frac{\sigma^2}{n}\right)$, $SE = \frac{\sigma}{\sqrt{n}}$ | Monte Carlo simulation drawing $N$ repeated samples of size $n$, demonstrating that the distribution of sample means converges to a bell curve regardless of population skewness. |
| **Confidence Intervals** | $\bar{x} \pm t_{\alpha/2, n-1} \cdot \left(\frac{s}{\sqrt{n}}\right)$ | Computes 90%, 95%, and 99% two-sided confidence intervals for population mean entropy and query length using Student's t-distribution. |
| **Hypothesis Testing (Welch's t-Test)** | $t = \frac{\bar{x}_1 - \bar{x}_2}{\sqrt{\frac{s_1^2}{n_1} + \frac{s_2^2}{n_2}}}$, $d = \frac{\bar{x}_1 - \bar{x}_2}{s_{\text{pooled}}}$ | Tests $H_0: \mu_{\text{tunnel}} = \mu_{\text{normal}}$ vs $H_1: \mu_{\text{tunnel}} \neq \mu_{\text{normal}}$; calculates p-values, degrees of freedom, Cohen's d effect size, and analyzes Type I ($\alpha$) and Type II ($\beta$) errors. |
| **Chi-Square Test of Independence ($\chi^2$)** | $\chi^2 = \sum \frac{(O_{ij} - E_{ij})^2}{E_{ij}}$, $df = (r-1)(c-1)$ | Evaluates contingency table between Query Length Categories (Short, Medium, Long) and Traffic Label (Normal vs Suspicious) to confirm statistical dependence. |
| **One-Way ANOVA** | $F = \frac{MS_{\text{between}}}{MS_{\text{within}}} = \frac{SS_B / (k-1)}{SS_W / (N-k)}$ | Compares mean entropy and length across different DNS Record Types (A, TXT, CNAME, AAAA) to test whether record type introduces significant variance. |
| **Correlation & Linear Regression** | $r = \frac{\text{Cov}(X, Y)}{s_x s_y}$, $\hat{y} = \beta_0 + \beta_1 x$ | Models Shannon Entropy as a linear function of Query Length; computes Pearson $r$, Spearman rank correlation $\rho$, $R^2$, slope, intercept, and standard error. |
| **Statistical Detection Benchmarking** | $\text{Sensitivity} = \frac{TP}{TP+FN}$, $\text{FPR} = \frac{FP}{FP+TN}$ | Compares 3 explainable detectors (Entropy-Only, Timing-Only, and Combined) with confusion matrices, precision, recall, and F1-score across configurable thresholds. |

---

## 3. Statistical Detection Engine

The web application provides interactive threshold tuning ($\theta_H$, $\theta_T$, $\theta_L$) to benchmark three explainable statistical detectors:

1. **Entropy-Only Detector ($\text{Entropy} \ge \theta_H$):**
   - High sensitivity to randomized base32/base64/hex payloads.
   - Prone to false alarms on long benign Content Delivery Network (CDN) domains.
2. **Timing-Only Detector ($\text{Inter-Arrival Time} \le \theta_T$):**
   - Flags automated bursts and tight beacon loops.
   - High false-positive rate during normal parallel web browsing sessions.
3. **Combined Statistical Detector:**
   - Multi-feature logical & standardized rule combining entropy with length constraints and timing bursts.
   - Drastically cuts false positives while maintaining high detection sensitivity ($\text{F1-score} > 0.95$).

---

## 4. Repository Structure

```
detection-of-DNS-tunneling-/
│
├── app.py                     # Flask web backend with statistical REST API endpoints
├── stats_engine.py            # Comprehensive statistical calculation library (NumPy, SciPy)
├── detector.py                # Rule-based & threshold statistical detection engine
├── dns_utils.py               # Shannon entropy, IAT, and feature extraction utilities
├── generate_data.py           # Script to generate realistic, labeled DNS datasets
│
├── data/                      # Sample datasets for project demonstration
│   ├── sample_dns_traffic.csv             # Balanced baseline dataset (1,200 records)
│   ├── sample_high_entropy_tunneling.csv  # High-intensity attack scenario (700 records)
│   └── sample_normal_workday.csv          # Enterprise routine browsing (920 records)
│
├── templates/
│   └── index.html             # Clean, responsive single-page dashboard with 8 academic tabs
│
├── static/
│   ├── css/
│   │   └── style.css          # Professional, student-developed layout & typography
│   └── js/
│       ├── chart.umd.min.js   # Local bundle of Chart.js for offline operation
│       └── main.js            # Frontend application logic, Chart.js visualizations & AJAX
│
├── tests/
│   └── test_stats.py          # Unit tests verifying mathematical formulas & endpoints
│
├── requirements.txt           # Project dependencies
├── .gitignore                 # Standard clean Git ignore rules
└── README.md                  # Comprehensive academic report & setup guide
```

---

## 5. Setup & Installation Instructions

### Prerequisites
- Python 3.8+ (tested on Python 3.10 and 3.11)
- `pip` (Python package manager)

### Step 1: Clone the Repository
```bash
git clone https://github.com/purvaa211/detection-of-DNS-tunneling-.git
cd detection-of-DNS-tunneling-
```

### Step 2: (Optional but recommended) Create a Virtual Environment
```bash
# On Windows (PowerShell):
python -m venv venv
.\venv\Scripts\Activate.ps1

# On Linux/macOS:
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run Unit Tests
Verify all statistical algorithms and functions pass:
```bash
python -m unittest discover tests
```
*Expected output: `Ran 12 tests in 0.03s ... OK`*

### Step 5: Start the Flask Application
```bash
python app.py
```

### Step 6: Access the Website
Open your web browser and navigate to:
```
http://localhost:5000
```

---

## 6. How to Use the Application

1. **Overview & Dataset Tab:**
   - Review active dataset summary metrics.
   - Filter, sort, and search raw DNS query records with calculated entropy and timing values.
   - Switch between sample datasets using the top dropdown or upload your own CSV file.
   - Click **"Export CSV"** to download the processed data with all computed features.
2. **Descriptive Statistics Tab:**
   - Toggle between Shannon Entropy, Query Length, and Inter-Arrival Time.
   - Inspect the comparative metrics table (Mean, Median, Mode, Variance, CV, IQR, Skewness, Kurtosis).
   - View binned frequency distribution histograms and read plain-English interpretations.
3. **Probability & Distributions Tab:**
   - Adjust prior attack rate and detector accuracy in the **Bayes' Theorem** playground to see real-time posterior probabilities and learn the Base Rate Fallacy.
   - Explore the **Binomial Distribution** batch model for query batches of size $n$.
   - Inspect the **Poisson Arrival Process** and **Exponential Inter-Arrival Time** curve fits.
4. **Sampling & CLT Tab:**
   - Select sample size $n$ and sample count $N$ to run a live **Monte Carlo Central Limit Theorem simulation**.
   - Check the 90%, 95%, and 99% **Confidence Intervals** table and Z-score normality tests.
5. **Hypothesis Testing & ANOVA Tab:**
   - Review **Welch's Two-Sample t-tests**, p-values, and Cohen's d effect sizes.
   - Study the Type I ($\alpha$) and Type II ($\beta$) error matrix.
   - Inspect the **Chi-Square Test of Independence** and **One-Way ANOVA** tables.
6. **Correlation & Regression Tab:**
   - Examine the scatter plot of Query Length vs Shannon Entropy with the fitted Ordinary Least Squares (OLS) line and $R^2$ variance explanation.
7. **Statistical Detection Tab:**
   - Adjust the threshold sliders ($\theta_H$, $\theta_T$, $\theta_L$) in real time.
   - Compare side-by-side $2 \times 2$ Confusion Matrices (TP, FP, TN, FN) and diagnostic metrics across all 3 detectors.
8. **Syllabus Reference & Report Tab:**
   - View the complete course syllabus mapping table and statistical assumptions guide.

---

## 7. Custom CSV Upload Guidelines

You can upload your own network trace CSV. The application accepts files with:
- **`query`** (or `domain`, `name`): The DNS domain name string (e.g. `google.com` or `a9b8c7.tunnel.com`).
- **`timestamp`** (or `time`, `datetime`): Formatted timestamp (e.g. `2026-10-18 09:30:00`).
- *Optional:* `label` (`Normal` or `Suspicious`), `record_type` (`A`, `TXT`, `CNAME`, etc.).

If statistical features (`entropy`, `query_length`, `inter_arrival_time`) are missing, the server automatically calculates them upon upload.

---

## 8. Academic Integrity & Pair Programming Attribution

This project was built for a college-level **Probability and Statistics** course. The focus is strictly educational: demonstrating how theoretical concepts from probability distributions, sampling, hypothesis testing, and regression apply directly to telemetry analysis.

- **Developer:** Purva Deshmukh ([@purvaa211](https://github.com/purvaa211))
- **Course:** Probability and Statistics Course Project
- **License:** Open Academic Demonstration