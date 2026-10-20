# Detecting DNS Tunneling Using Entropy and Timing Statistics

**Course Project:** Probability and Statistics (College Curriculum Demonstration)  
**Web Framework:** Python Flask, SciPy, NumPy, and Chart.js  

---

## 1. Project Overview & Statistical Objective

This project uses domain name query telemetry as a real-world dataset to demonstrate core **Probability and Mathematical Statistics** concepts. Rather than focusing on complex cybersecurity mechanisms, the project emphasizes statistical modeling, hypothesis testing, distributions, and regression.

We analyze two primary continuous random variables:
1. **Shannon Entropy ($H$):** Measures character randomness in bits per character:
   $$H(X) = - \sum_{i=1}^{n} p_i \log_2(p_i)$$
   Normal English domain names have natural orthographic patterns and lower entropy ($\sim 2.0 - 3.4$ bits/char). Encoded or suspicious queries exhibit high randomness ($\sim 4.0 - 4.9$ bits/char).
2. **Inter-Arrival Time ($\Delta t$):** Measures the time gap between successive queries in seconds. Normal human web browsing generates variable, bursty intervals, whereas automated scripts often generate rapid bursts or periodic beaconing.

---

## 2. Website Navigation & Sections

The application is streamlined into **4 clean, interactive sections** designed for college viva presentation:

### 1. Overview
- Summary metric cards showing total queries, normal vs. suspicious counts and percentages, mean query length, mean Shannon entropy, and mean inter-arrival time.
- Searchable, filterable, and paginated interactive DNS query records table.
- Active dataset selector allowing instant switching between sample datasets (Mixed Baseline, Attack Surge, and Routine Browsing) with CSV export capability.

### 2. Data Analysis
- Complete descriptive statistics table: Sample size ($n$), Mean ($\bar{x}$), Median ($Q_2$), Sample Variance ($s^2$), Standard Deviation ($s$), Coefficient of Variation ($CV\%$), 1st Quartile ($Q_1$), 3rd Quartile ($Q_3$), Interquartile Range ($IQR$), and Range.
- Feature selector: Shannon Entropy (bits/char), Query Length (chars), and Inter-Arrival Time (seconds).
- Binned frequency distribution histograms comparing Normal vs. Suspicious queries.
- Plain-English viva explanations beneath graphs explaining central tendency, variability ($CV$), and group separation.

### 3. Probability & Distributions
- **Empirical Base Rates:** $P(\text{Normal})$ and $P(\text{Suspicious})$ from dataset.
- **Bayes' Theorem & The Base Rate Fallacy:** Conditional probability analysis demonstrating why false alarms occur when prior base rates are low:
  $$P(\text{Suspicious} \mid \text{Alarm}) = \frac{P(\text{Alarm} \mid \text{Suspicious}) P(\text{Suspicious})}{P(\text{Alarm})}$$
- **Binomial Distribution Model:** Models the count of suspicious queries $X \sim \text{Binomial}(n, p)$ in a sliding batch of $n$ queries with PMF bar chart, expected value $E[X] = np$, and variance $\text{Var}(X) = np(1-p)$.
- **Normal Distribution Fit & Confidence Interval:** Evaluates empirical entropy against a normal distribution curve and calculates the **95% Confidence Interval for the mean entropy** using Student's t-distribution:
  $$\bar{x} \pm t_{\alpha/2, n-1} \cdot \left(\frac{s}{\sqrt{n}}\right)$$

### 4. Hypothesis Testing
- **Welch's Two-Sample t-Test:** Compares normal vs. suspicious traffic without assuming equal population variances:
  $$H_0: \mu_{\text{normal}} = \mu_{\text{suspicious}} \quad \text{vs} \quad H_1: \mu_{\text{normal}} \neq \mu_{\text{suspicious}}$$
- Evaluates test statistics, degrees of freedom, Cohen's d effect size, and p-values for Entropy, Query Length, and Inter-Arrival Time.
- Clear viva conclusion explaining that $p < 0.001$ rejects $H_0$ and proves statistically significant separation.
- Explanation of Type I Error (False Positive, $\alpha$) and Type II Error (False Negative, $\beta$).

---

## 3. Project Directory Structure

```
detection-of-DNS-tunneling-/
├── app.py                     # Flask web backend with statistical REST API endpoints
├── stats_engine.py            # Statistical computation library (NumPy, SciPy)
├── detector.py                # Rule-based threshold detection benchmark
├── dns_utils.py               # Shannon entropy, IAT, and CSV validation utilities
├── generate_data.py           # Script to generate realistic sample datasets
├── data/                      # Sample datasets
│   ├── sample_dns_traffic.csv             # Baseline mixed dataset (1,200 rows)
│   ├── sample_high_entropy_tunneling.csv  # High-suspicious attack surge (700 rows)
│   └── sample_normal_workday.csv          # Routine enterprise browsing (920 rows)
├── templates/
│   └── index.html             # Clean 5-section responsive dashboard
├── static/
│   ├── css/
│   │   └── style.css          # Restrained, modern typography & card styling
│   └── js/
│       ├── chart.umd.min.js   # Local Chart.js bundle for offline execution
│       └── main.js            # Frontend application logic & Chart.js rendering
├── tests/
│   ├── test_stats.py          # Unit tests verifying mathematical formulas
│   └── test_app.py            # Integration tests verifying API endpoints & validation
├── requirements.txt           # Python dependencies
├── .gitignore                 # Clean Git ignore rules
└── README.md                  # Project documentation & viva guide
```

---

## 4. Setup & Running Instructions

### Prerequisites
- Python 3.8+ (tested on Python 3.10 and 3.11)
- `pip`

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Run Automated Tests
```bash
python -m unittest discover tests
```
*Expected: `Ran 25 tests in ~0.26s ... OK`*

### Step 3: Start the Flask Application
```bash
python app.py
```

### Step 4: Open in Web Browser
Navigate to **`http://localhost:5000`** (or `http://127.0.0.1:5000`).

---

## 5. Viva Talking Points for Students

1. **Why use Shannon Entropy?** Natural language words use repeated vowels and common letters, producing lower entropy ($\sim 2.5 - 3.2$ bits). Encoded data (Base32/Base64/Hex) distributes characters uniformly, resulting in higher entropy ($\sim 4.2 - 4.8$ bits).
2. **What does the p-value mean in your t-test?** A p-value $< 0.0001$ means there is less than a $0.01\%$ probability that the observed difference between normal and suspicious queries was a fluke of random sampling. Therefore, we reject the null hypothesis $H_0$.
3. **What is the Base Rate Fallacy?** If suspicious queries are rare ($P(\text{Suspicious}) = 5\%$), even a $94\%$ sensitive detector can produce a noticeable number of false alarms because legitimate queries dominate overall network traffic.
4. **Why combine entropy and timing?** Entropy alone can flag long benign CDN domains (false positive). Timing alone can flag parallel browser tabs. Combining them produces a lower false-positive rate.

---

## 6. Academic Integrity & Authors

- **Student Author:** Purva Deshmukh ([@purvaa211](https://github.com/purvaa211))
- **Course:** Probability and Statistics Course Project
- **License:** Open Academic Educational Project
