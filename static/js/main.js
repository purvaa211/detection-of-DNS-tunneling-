/**
 * DNS StatLab - Probability & Statistics Platform
 * Frontend Application Controller
 */

// Global Chart Instances
const charts = {};

function destroyChart(name) {
  if (charts[name]) {
    charts[name].destroy();
    delete charts[name];
  }
}

// Global Application State
const state = {
  activeTab: 'tab-overview',
  activeDataset: 'sample_dns_traffic.csv',
  recordsPage: 1,
  recordsPageSize: 12,
  recordsSortBy: 'timestamp',
  recordsSortOrder: 'asc',
  recordsSearch: '',
  recordsLabelFilter: 'all',
  descriptiveCache: null,
  selectedDescFeature: 'query_length',
  selectedUploadFile: null
};

// Section Metadata for Top Bar
const sectionHeaders = {
  'tab-overview': {
    title: 'Overview & Dataset Telemetry',
    desc: 'Summary statistics, class proportions, and searchable traffic records'
  },
  'tab-descriptive': {
    title: 'Descriptive Statistics & Data Spread',
    desc: 'Measures of central tendency, dispersion, quartiles, and frequency histograms'
  },
  'tab-probability': {
    title: 'Probability & Distribution Models',
    desc: 'Bayesian conditioning, Normal distribution, Poisson arrivals, and Exponential timing'
  },
  'tab-regression': {
    title: 'Correlation & Regression Analysis',
    desc: 'Pearson/Spearman matrix, Simple OLS regression, and Multiple Linear Regression'
  },
  'tab-hypothesis': {
    title: 'Hypothesis Testing & Confidence Intervals',
    desc: "Two-sample Welch's t-test, Cohen's d effect sizes, and Student's t confidence intervals"
  },
  'tab-anomaly': {
    title: 'Statistical Anomaly Detection',
    desc: 'Comparative outlier analysis using Z-Score (parametric) and IQR (non-parametric) methods'
  },
  'tab-detection': {
    title: 'DNS Tunneling Detection Results',
    desc: 'Rule-based benchmark, diagnostic confusion matrix, and performance trade-offs'
  }
};

// =====================================================================
// 1. Navigation & Tab Switching
// =====================================================================

function initNavigation() {
  const sidebarButtons = document.querySelectorAll('.sidebar-btn');
  sidebarButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });

  // Topbar refresh button
  document.getElementById('btn-refresh-data')?.addEventListener('click', () => {
    state.descriptiveCache = null;
    loadAllDataForActiveTab();
  });
}

function switchTab(tabId) {
  state.activeTab = tabId;

  // Update button active state
  document.querySelectorAll('.sidebar-btn').forEach(b => {
    b.classList.toggle('active', b.getAttribute('data-tab') === tabId);
  });

  // Update content active state
  document.querySelectorAll('.tab-content').forEach(c => {
    c.classList.toggle('active', c.id === tabId);
  });

  // Update Topbar
  const headerInfo = sectionHeaders[tabId] || {
    title: 'DNS Tunneling Statistics Platform',
    desc: 'Probability and Statistics Project'
  };
  const titleEl = document.getElementById('topbar-section-title');
  const descEl = document.getElementById('topbar-section-desc');
  if (titleEl) titleEl.textContent = headerInfo.title;
  if (descEl) descEl.textContent = headerInfo.desc;

  // Load section-specific data
  loadAllDataForActiveTab();
}

function loadAllDataForActiveTab() {
  switch (state.activeTab) {
    case 'tab-overview':
      loadOverviewData();
      break;
    case 'tab-descriptive':
      loadDescriptiveStats();
      break;
    case 'tab-probability':
      loadProbabilityData();
      break;
    case 'tab-regression':
      loadCorrelationData();
      loadSimpleRegression();
      loadMultipleRegression();
      break;
    case 'tab-hypothesis':
      loadHypothesisData();
      break;
    case 'tab-anomaly':
      loadAnomalyData();
      break;
    case 'tab-detection':
      loadDetectionResults();
      break;
  }
}

// =====================================================================
// 2. Overview Section Controller
// =====================================================================

async function loadOverviewData() {
  try {
    const res = await fetch('/api/dataset/info');
    const data = await res.json();
    if (data.status !== 'success') return;

    state.activeDataset = data.dataset_name;

    // Update Topbar Badge
    const topBadge = document.getElementById('topbar-dataset-badge');
    if (topBadge) topBadge.textContent = data.dataset_name;

    // Update Sidebar Widget
    const sideMode = document.getElementById('sidebar-dataset-mode');
    const sideCount = document.getElementById('sidebar-dataset-count');
    if (sideMode) sideMode.textContent = data.is_simulated ? "Sample Data" : "Custom CSV";
    if (sideCount) sideCount.textContent = `${data.total_queries.toLocaleString()} rows`;

    // Populate Sidebar Selector if needed
    populateDatasetSelector(data.available_datasets, data.dataset_name);

    // Update 8 Metric Cards
    setElText('ov-metric-total', data.total_queries.toLocaleString());
    setElText('ov-metric-normal', `${data.normal_queries.toLocaleString()} (${data.normal_pct}%)`);
    setElText('ov-metric-suspicious', `${data.suspicious_queries.toLocaleString()} (${data.suspicious_pct}%)`);
    setElText('ov-metric-susp-pct', `${data.suspicious_pct}%`);
    setElText('ov-metric-length', `${data.mean_length} chars`);
    setElText('ov-metric-frequency', `${data.mean_frequency} q/10s`);
    setElText('ov-metric-iat', `${data.mean_iat_seconds} s`);
    setElText('ov-metric-outliers', data.total_outliers_detected || 0);

    // Key Observations List
    const obsListEl = document.getElementById('overview-observations-list');
    if (obsListEl && data.observations) {
      obsListEl.innerHTML = data.observations.map(obs => `
        <div class="note-box" style="margin-top:0;">• ${obs}</div>
      `).join('');
    }

    // Render Traffic Class Chart
    renderOverviewTrafficChart(data.normal_queries, data.suspicious_queries);

    // Load records table
    loadDatasetRecords();
  } catch (err) {
    console.error("Failed to load overview data:", err);
  }
}

function populateDatasetSelector(datasets, activeName) {
  const select = document.getElementById('sidebar-dataset-select');
  if (!select) return;
  select.innerHTML = '';
  datasets.forEach(filename => {
    const opt = document.createElement('option');
    opt.value = filename;
    let label = filename;
    if (filename === 'sample_dns_traffic.csv') label = 'Mixed Baseline (1,200 rows)';
    else if (filename === 'sample_high_entropy_tunneling.csv') label = 'Attack Surge (700 rows)';
    else if (filename === 'sample_normal_workday.csv') label = 'Routine Browsing (920 rows)';
    opt.textContent = label;
    if (filename === activeName) opt.selected = true;
    select.appendChild(opt);
  });
}

function renderOverviewTrafficChart(normalCount, suspiciousCount) {
  destroyChart('overviewTraffic');
  const canvas = document.getElementById('overviewTrafficChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  charts['overviewTraffic'] = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Normal Browsing Traffic', 'Suspicious Tunneling Queries'],
      datasets: [{
        data: [normalCount, suspiciousCount],
        backgroundColor: ['rgba(102, 124, 105, 0.85)', 'rgba(183, 123, 97, 0.85)'],
        borderColor: ['#667C69', '#B77B61'],
        borderWidth: 1.5,
        hoverOffset: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { boxWidth: 14, font: { size: 12 } }
        },
        tooltip: {
          callbacks: {
            label: function(ctx) {
              const total = normalCount + suspiciousCount;
              const pct = ((ctx.parsed / total) * 100).toFixed(1);
              return ` ${ctx.label}: ${ctx.parsed.toLocaleString()} (${pct}%)`;
            }
          }
        }
      },
      cutout: '62%'
    }
  });
}

async function loadDatasetRecords() {
  const params = new URLSearchParams({
    page: state.recordsPage,
    page_size: state.recordsPageSize,
    search: state.recordsSearch,
    label: state.recordsLabelFilter,
    sort_by: state.recordsSortBy,
    sort_order: state.recordsSortOrder
  });

  try {
    const res = await fetch(`/api/dataset/records?${params.toString()}`);
    const data = await res.json();
    if (data.status !== 'success') return;

    const tbody = document.getElementById('dns-records-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!data.records || data.records.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 24px; color: var(--text-secondary);">No matching DNS queries found.</td></tr>`;
    } else {
      data.records.forEach(row => {
        const tr = document.createElement('tr');
        const badgeClass = row.label === 'Suspicious' ? 'badge-suspicious' : 'badge-normal';
        tr.innerHTML = `
          <td>${row.timestamp}</td>
          <td><code style="font-size: 0.82rem; font-family: var(--font-mono); word-break: break-all;">${row.query}</code></td>
          <td><span class="badge badge-info">${row.record_type}</span></td>
          <td class="numeric">${row.query_length}</td>
          <td class="numeric">${row.entropy.toFixed(3)}</td>
          <td class="numeric">${row.inter_arrival_time.toFixed(4)}</td>
          <td class="numeric">${row.query_frequency.toFixed(1)}</td>
          <td><span class="badge ${badgeClass}">${row.label}</span></td>
        `;
        tbody.appendChild(tr);
      });
    }

    setElText('page-info', `Page ${data.page} of ${data.total_pages} (${data.total_records.toLocaleString()} records)`);
    const prevBtn = document.getElementById('btn-prev-page');
    const nextBtn = document.getElementById('btn-next-page');
    if (prevBtn) prevBtn.disabled = (data.page <= 1);
    if (nextBtn) nextBtn.disabled = (data.page >= data.total_pages);
  } catch (err) {
    console.error("Failed to load records:", err);
  }
}

// =====================================================================
// 3. Descriptive Statistics Section Controller
// =====================================================================

async function loadDescriptiveStats() {
  try {
    if (!state.descriptiveCache) {
      const res = await fetch('/api/stats/descriptive');
      const data = await res.json();
      if (data.status !== 'success') return;
      state.descriptiveCache = data.features;
    }
    updateDescriptiveView();
  } catch (err) {
    console.error("Failed to load descriptive stats:", err);
  }
}

function updateDescriptiveView() {
  if (!state.descriptiveCache) return;
  const feat = document.getElementById('desc-feature-select')?.value || state.selectedDescFeature;
  state.selectedDescFeature = feat;

  const featData = state.descriptiveCache[feat];
  if (!featData) return;

  const n = featData.descriptive.normal;
  const s = featData.descriptive.suspicious;
  const o = featData.descriptive.overall;

  const rows = [
    { label: "Sample Size (n)", n: n.n, s: s.n, o: o.n, formula: "Count of valid observations", fmt: v => v.toLocaleString() },
    { label: "Sample Mean (x̄)", n: n.mean, s: s.mean, o: o.mean, formula: "x̄ = (Σ x_i) / n", fmt: v => v.toFixed(4) },
    { label: "Median (Q2)", n: n.median, s: s.median, o: o.median, formula: "50th percentile rank", fmt: v => v.toFixed(4) },
    { label: "Mode", n: n.mode, s: s.mode, o: o.mode, formula: "Most frequent value", fmt: v => v.toFixed(4) },
    { label: "Sample Variance (s²)", n: n.sample_variance, s: s.sample_variance, o: o.sample_variance, formula: "s² = Σ(x - x̄)² / (n - 1)", fmt: v => v.toFixed(4) },
    { label: "Sample Standard Deviation (s)", n: n.sample_std, s: s.sample_std, o: o.sample_std, formula: "s = √(sample variance)", fmt: v => v.toFixed(4) },
    { label: "Standard Error (SE)", n: n.standard_error, s: s.standard_error, o: o.standard_error, formula: "SE = s / √n", fmt: v => v.toFixed(4) },
    { label: "Coefficient of Variation (CV%)", n: n.coefficient_of_variation_pct, s: s.coefficient_of_variation_pct, o: o.coefficient_of_variation_pct, formula: "CV = (s / x̄) × 100", fmt: v => v.toFixed(2) + '%' },
    { label: "Minimum & Maximum", n: `${n.min} to ${n.max}`, s: `${s.min} to ${s.max}`, o: `${o.min} to ${o.max}`, formula: "Range extreme boundaries", fmt: v => v },
    { label: "First Quartile (Q1)", n: n.q1, s: s.q1, o: o.q1, formula: "25th percentile", fmt: v => v.toFixed(4) },
    { label: "Third Quartile (Q3)", n: n.q3, s: s.q3, o: o.q3, formula: "75th percentile", fmt: v => v.toFixed(4) },
    { label: "Interquartile Range (IQR)", n: n.iqr, s: s.iqr, o: o.iqr, formula: "IQR = Q3 - Q1", fmt: v => v.toFixed(4) },
    { label: "Skewness", n: n.skewness, s: s.skewness, o: o.skewness, formula: "m₃ / s³ (Third standardized moment)", fmt: v => v.toFixed(3) },
    { label: "Excess Kurtosis", n: n.kurtosis, s: s.kurtosis, o: o.kurtosis, formula: "m₄ / s⁴ - 3 (Tail heaviness)", fmt: v => v.toFixed(3) }
  ];

  const tbody = document.getElementById('desc-stats-tbody');
  if (tbody) {
    tbody.innerHTML = rows.map(r => `
      <tr>
        <td><strong>${r.label}</strong></td>
        <td class="numeric">${r.fmt(r.n)}</td>
        <td class="numeric">${r.fmt(r.s)}</td>
        <td class="numeric">${r.fmt(r.o)}</td>
        <td style="color:var(--text-secondary); font-size:0.8rem;"><code>${r.formula}</code></td>
      </tr>
    `).join('');
  }

  // Render Histogram
  renderHistogramChart(feat, featData.histograms);

  // Render Five-Number Boxplot Visual
  renderBoxplotVisual(feat, featData.boxplot);

  // Update Dynamic Interpretation
  const unit = feat.includes('length') ? 'characters' : feat.includes('time') ? 'seconds' : feat.includes('frequency') ? 'q/10s' : 'bits';
  const diffPct = (((s.mean - n.mean) / (n.mean || 1)) * 100).toFixed(1);
  const interpEl = document.getElementById('desc-interpretation-text');
  if (interpEl) {
    interpEl.innerHTML = `
      <strong>Statistical Takeaways for ${feat.replace('_', ' ').toUpperCase()}:</strong><br>
      • <strong>Central Tendency:</strong> Normal queries average <code>${n.mean} ${unit}</code> (median ${n.median}), while suspicious queries average <code>${s.mean} ${unit}</code> (median ${s.median}), representing a <strong>${Math.abs(diffPct)}% ${diffPct >= 0 ? 'increase' : 'decrease'}</strong>.<br>
      • <strong>Relative Dispersion:</strong> Normal CV is <code>${n.coefficient_of_variation_pct}%</code> versus Suspicious CV <code>${s.coefficient_of_variation_pct}%</code>. A lower CV indicates tighter clustering around the mean.<br>
      • <strong>Distribution Shape:</strong> Skewness is ${o.skewness > 0.5 ? 'positively skewed (right tail)' : o.skewness < -0.5 ? 'negatively skewed (left tail)' : 'approximately symmetric'}. The binned frequency histogram demonstrates distinct separation between benign and anomalous traffic distributions.
    `;
  }
}

function renderHistogramChart(feature, histograms) {
  destroyChart('descHistogram');
  const canvas = document.getElementById('descHistogramChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  const norm = histograms.normal;
  const susp = histograms.suspicious;
  const labels = norm.labels.length >= susp.labels.length ? norm.labels : susp.labels;

  charts['descHistogram'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Normal Traffic Frequency',
          data: norm.counts,
          backgroundColor: 'rgba(102, 124, 105, 0.8)',
          borderColor: '#667C69',
          borderWidth: 1
        },
        {
          label: 'Suspicious Traffic Frequency',
          data: susp.counts,
          backgroundColor: 'rgba(183, 123, 97, 0.8)',
          borderColor: '#B77B61',
          borderWidth: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'top', labels: { boxWidth: 12, font: { size: 11 } } },
        tooltip: { mode: 'index', intersect: false }
      },
      scales: {
        x: {
          title: { display: true, text: `${feature.replace('_', ' ').toUpperCase()} Bins`, font: { weight: '600', size: 11 } },
          grid: { color: 'rgba(228, 225, 216, 0.7)' }
        },
        y: {
          title: { display: true, text: 'Query Count (Frequency)', font: { weight: '600', size: 11 } },
          beginAtZero: true,
          grid: { color: 'rgba(228, 225, 216, 0.7)' }
        }
      }
    }
  });
}

function renderBoxplotVisual(feature, boxplotData) {
  const container = document.getElementById('boxplot-rows-list');
  if (!container || !boxplotData) return;

  const groups = ['Normal', 'Suspicious', 'Overall'];
  container.innerHTML = groups.map(grp => {
    const d = boxplotData[grp] || { min: 0, q1: 0, median: 0, q3: 0, max: 0, outliers_count: 0 };
    return `
      <div style="padding:10px 12px; margin-bottom:8px; background:#FFFFFF; border:1px solid var(--border-color); border-radius:6px;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:4px;">
          <strong style="color:var(--dark-accent); font-size:0.86rem;">${grp} Traffic</strong>
          <span style="font-size:0.75rem; color:var(--text-secondary);">${d.outliers_count} outliers outside whiskers</span>
        </div>
        <div style="font-size:0.78rem; color:var(--text-main); font-family:var(--font-mono); line-height:1.6;">
          Min: ${d.min} | Q1: ${d.q1} | Median: <strong>${d.median}</strong> | Q3: ${d.q3} | Max: ${d.max} | IQR: ${d.iqr || (d.q3 - d.q1).toFixed(2)}
        </div>
      </div>
    `;
  }).join('');
}

// =====================================================================
// 4. Probability & Distributions Section Controller
// =====================================================================

async function loadProbabilityData() {
  const normFeat = document.getElementById('prob-normal-feature')?.value || 'query_length';
  const timeBucket = parseFloat(document.getElementById('poisson-interval-select')?.value || '2.0');

  try {
    const res = await fetch('/api/stats/probability', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        normal_feature: normFeat,
        time_bucket_seconds: timeBucket,
        n_batch: 30
      })
    });
    const data = await res.json();
    if (data.status !== 'success') return;

    // Empirical Base Rates
    const ep = data.empirical_probs;
    setElText('prob-p-normal', `${(ep.p_normal * 100).toFixed(1)}% (${ep.normal_count.toLocaleString()} queries)`);
    setElText('prob-p-suspicious', `${(ep.p_suspicious * 100).toFixed(1)}% (${ep.suspicious_count.toLocaleString()} queries)`);

    // Bayes' Theorem
    const bayes = data.bayes_theorem;
    setElText('bayes-posterior-val', `${bayes.posterior_pct}%`);
    setElText('bayes-npv-val', `${(bayes.posterior_normal_given_no_alarm * 100).toFixed(1)}%`);
    setElHtml('bayes-note-text', `
      <strong>Base Rate Fallacy:</strong> Sensitivity = ${(bayes.sensitivity * 100).toFixed(0)}%, False Positive Rate = ${(bayes.false_positive_rate * 100).toFixed(0)}%.
      Because normal queries comprise ${(bayes.prior_normal * 100).toFixed(1)}% of total traffic, the probability of a true positive given an alarm is <strong>${bayes.posterior_pct}%</strong>.
    `);

    // Normal Fit
    const nf = data.normal_fit;
    if (nf && nf.ci_95) {
      setElText('prob-ci95-val', `[ ${nf.ci_95.lower_bound} , ${nf.ci_95.upper_bound} ]`);
      if (nf.empirical_rule) {
        setElText('prob-rule-1sd', `${nf.empirical_rule.within_1_sigma_pct}%`);
        setElText('prob-rule-2sd', `${nf.empirical_rule.within_2_sigma_pct}%`);
        setElText('prob-rule-3sd', `${nf.empirical_rule.within_3_sigma_pct}%`);
      }
      setElText('prob-normality-verdict', nf.interpretation);
      renderNormalDistributionChart(nf);
    }

    // Poisson Process
    const poisson = data.poisson_process;
    if (poisson) {
      setElText('poisson-lambda-val', `Arrival Rate λ = ${poisson.estimated_lambda} queries / ${poisson.time_bucket_seconds}s`);
      setElText('poisson-vmr-val', `Dispersion VMR = ${poisson.dispersion_ratio_vmr}`);
      setElText('poisson-interpretation-text', poisson.interpretation);
      renderPoissonChart(poisson);
    }

    // Exponential IAT
    const expon = data.exponential_iat;
    if (expon) {
      if (expon.Normal) setElText('expon-rate-normal', `Normal λ = ${expon.Normal.estimated_lambda} (mean ${expon.Normal.mean_iat}s)`);
      if (expon.Suspicious) setElText('expon-rate-susp', `Suspicious λ = ${expon.Suspicious.estimated_lambda} (mean ${expon.Suspicious.mean_iat}s)`);
      renderExponentialChart(expon);
    }

    // Binomial Batch
    const binom = data.binomial_batch;
    if (binom) {
      setElText('binom-mean-val', `Expected Value E[X] = ${binom.mean}`);
      setElText('binom-var-val', `Variance = ${binom.variance} (σ = ${binom.std_dev})`);
      renderBinomialChart(binom);
    }
  } catch (err) {
    console.error("Failed to load probability models:", err);
  }
}

function renderNormalDistributionChart(nf) {
  destroyChart('normalDist');
  const canvas = document.getElementById('normalDistributionChartCanvas');
  if (!canvas || !nf.normal_curve) return;
  const ctx = canvas.getContext('2d');

  charts['normalDist'] = new Chart(ctx, {
    type: 'line',
    data: {
      labels: nf.normal_curve.x_values,
      datasets: [{
        label: `Theoretical Normal PDF Curve (μ = ${nf.mean}, σ = ${nf.std_dev})`,
        data: nf.normal_curve.pdf_values,
        borderColor: '#403747',
        backgroundColor: 'rgba(64, 55, 71, 0.15)',
        fill: true,
        borderWidth: 2,
        tension: 0.35,
        pointRadius: 0
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'top', labels: { boxWidth: 12, font: { size: 11 } } }
      },
      scales: {
        x: { title: { display: true, text: `${nf.feature.replace('_', ' ').toUpperCase()} Value` } },
        y: { title: { display: true, text: 'Probability Density f(x)' }, beginAtZero: true }
      }
    }
  });
}

function renderPoissonChart(poisson) {
  destroyChart('poissonChart');
  const canvas = document.getElementById('poissonChartCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  charts['poissonChart'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: poisson.k_vals,
      datasets: [
        {
          label: 'Observed Empirical Frequencies',
          data: poisson.empirical_frequencies,
          backgroundColor: 'rgba(102, 124, 105, 0.8)',
          borderColor: '#667C69',
          borderWidth: 1
        },
        {
          type: 'line',
          label: `Theoretical Poisson PMF (λ = ${poisson.estimated_lambda})`,
          data: poisson.theoretical_poisson,
          borderColor: '#403747',
          backgroundColor: 'transparent',
          borderWidth: 2,
          pointRadius: 3
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { title: { display: true, text: `Queries in ${poisson.time_bucket_seconds}s Window (k)` } },
        y: { title: { display: true, text: 'Probability P(X = k)' }, beginAtZero: true }
      }
    }
  });
}

function renderExponentialChart(expon) {
  destroyChart('exponentialChart');
  const canvas = document.getElementById('exponentialChartCanvas');
  if (!canvas || !expon.Normal) return;
  const ctx = canvas.getContext('2d');

  charts['exponentialChart'] = new Chart(ctx, {
    type: 'line',
    data: {
      labels: expon.Normal.midpoints,
      datasets: [
        {
          label: `Normal Observed IAT Frequency`,
          data: expon.Normal.empirical,
          borderColor: '#667C69',
          backgroundColor: 'rgba(102, 124, 105, 0.2)',
          fill: true,
          borderWidth: 1.5,
          tension: 0.3
        },
        {
          label: `Suspicious Observed IAT Frequency`,
          data: expon.Suspicious ? expon.Suspicious.empirical : [],
          borderColor: '#B77B61',
          backgroundColor: 'rgba(183, 123, 97, 0.2)',
          fill: true,
          borderWidth: 1.5,
          tension: 0.3
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { title: { display: true, text: 'Inter-Arrival Time (seconds)' } },
        y: { title: { display: true, text: 'Relative Frequency' }, beginAtZero: true }
      }
    }
  });
}

function renderBinomialChart(binom) {
  destroyChart('binomialChart');
  const canvas = document.getElementById('binomialChartCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  charts['binomialChart'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: binom.k_values.slice(0, 16),
      datasets: [{
        label: `Probability P(X = k) in Batch n = ${binom.n}`,
        data: binom.pmf.slice(0, 16),
        backgroundColor: 'rgba(64, 55, 71, 0.8)',
        borderColor: '#403747',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { title: { display: true, text: 'Suspicious Queries in Batch (k)' } },
        y: { title: { display: true, text: 'Probability P(X = k)' }, beginAtZero: true }
      }
    }
  });
}

// =====================================================================
// 5. Correlation & Regression Section Controller
// =====================================================================

async function loadCorrelationData() {
  const xCol = document.getElementById('corr-x-select')?.value || 'query_length';
  const yCol = document.getElementById('corr-y-select')?.value || 'entropy';

  try {
    const res = await fetch(`/api/stats/correlation?x_col=${xCol}&y_col=${yCol}`);
    const data = await res.json();
    if (data.status !== 'success') return;

    // Populate Selectors if empty
    populateCorrSelectors(data.matrix.features, xCol, yCol);

    // Render Matrix Table
    renderCorrelationMatrixTable(data.matrix);

    // Render Scatter Chart
    const pair = data.pair_selected;
    setElText('corr-pair-title', `${pair.x_col} vs ${pair.y_col}`);
    setElText('corr-pair-r', `Pearson r = ${pair.pearson_r}, Spearman ρ = ${pair.spearman_rho}`);
    renderCorrScatterChart(pair);
  } catch (err) {
    console.error("Failed to load correlation data:", err);
  }
}

function populateCorrSelectors(features, activeX, activeY) {
  const xSel = document.getElementById('corr-x-select');
  const ySel = document.getElementById('corr-y-select');
  if (!xSel || !ySel || xSel.children.length > 0) return;

  features.forEach(f => {
    const optX = document.createElement('option');
    optX.value = f;
    optX.textContent = f.replace('_', ' ').toUpperCase();
    if (f === activeX) optX.selected = true;
    xSel.appendChild(optX);

    const optY = document.createElement('option');
    optY.value = f;
    optY.textContent = f.replace('_', ' ').toUpperCase();
    if (f === activeY) optY.selected = true;
    ySel.appendChild(optY);
  });
}

function renderCorrelationMatrixTable(matrixData) {
  const container = document.getElementById('correlation-matrix-table');
  if (!container || !matrixData.features) return;

  const feats = matrixData.features;
  const pMat = matrixData.pearson_matrix;

  let html = `<table class="stats-table"><thead><tr><th>Feature</th>`;
  feats.forEach(f => {
    html += `<th class="numeric">${f.replace('_', ' ').substring(0, 10)}</th>`;
  });
  html += `</tr></thead><tbody>`;

  feats.forEach((rowFeat, r) => {
    html += `<tr><td><strong>${rowFeat}</strong></td>`;
    feats.forEach((_, c) => {
      const val = pMat[r][c];
      const bgStyle = val === 1 ? 'background:#FAF8F5; font-weight:800;' :
                      val > 0.6 ? 'background:rgba(102, 124, 105, 0.22); color:#403747; font-weight:700;' :
                      val < -0.3 ? 'background:rgba(183, 123, 97, 0.22); color:#403747;' : '';
      html += `<td class="numeric" style="${bgStyle}">${val.toFixed(3)}</td>`;
    });
    html += `</tr>`;
  });
  html += `</tbody></table>`;
  container.innerHTML = html;
}

function renderCorrScatterChart(pair) {
  destroyChart('corrScatter');
  const canvas = document.getElementById('corrScatterChartCanvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  charts['corrScatter'] = new Chart(ctx, {
    type: 'scatter',
    data: {
      datasets: [
        {
          label: 'Normal Traffic',
          data: pair.scatter_normal,
          backgroundColor: 'rgba(102, 124, 105, 0.65)',
          borderColor: '#667C69',
          pointRadius: 3
        },
        {
          label: 'Suspicious Traffic',
          data: pair.scatter_suspicious,
          backgroundColor: 'rgba(183, 123, 97, 0.75)',
          borderColor: '#B77B61',
          pointRadius: 3.5
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { position: 'top', labels: { boxWidth: 12 } } },
      scales: {
        x: { title: { display: true, text: pair.x_col.replace('_', ' ').toUpperCase() } },
        y: { title: { display: true, text: pair.y_col.replace('_', ' ').toUpperCase() } }
      }
    }
  });
}

async function loadSimpleRegression() {
  const xCol = document.getElementById('slr-x-select')?.value || 'query_length';
  const yCol = document.getElementById('slr-y-select')?.value || 'entropy';

  try {
    const res = await fetch(`/api/stats/regression?x_col=${xCol}&y_col=${yCol}`);
    const data = await res.json();
    if (data.status !== 'success') return;

    const reg = data.regression;
    setElText('slr-equation', `${reg.y_col} = ${reg.intercept} + (${reg.slope} × ${reg.x_col})`);
    setElText('slr-r2', `${(reg.r_squared * 100).toFixed(1)}% (R² = ${reg.r_squared})`);
    setElText('slr-mse', `${reg.mse} (RMSE = ${reg.rmse})`);
    setElText('slr-interpretation-text', reg.interpretation);

    renderSLRCharts(reg);
  } catch (err) {
    console.error("Failed to load simple regression:", err);
  }
}

function renderSLRCharts(reg) {
  // 1. Fitted Line
  destroyChart('slrScatter');
  const canvas1 = document.getElementById('slrScatterCanvas');
  if (canvas1) {
    const ctx1 = canvas1.getContext('2d');
    charts['slrScatter'] = new Chart(ctx1, {
      type: 'scatter',
      data: {
        datasets: [
          {
            label: 'Data Observations',
            data: reg.scatter_points,
            backgroundColor: 'rgba(102, 124, 105, 0.55)',
            borderColor: '#667C69',
            pointRadius: 3
          },
          {
            type: 'line',
            label: `Fitted Line (y = ${reg.intercept} + ${reg.slope}x)`,
            data: reg.regression_line,
            borderColor: '#403747',
            borderWidth: 2.5,
            fill: false,
            pointRadius: 0
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { title: { display: true, text: reg.x_col } },
          y: { title: { display: true, text: reg.y_col } }
        }
      }
    });
  }

  // 2. Residuals Plot
  destroyChart('slrResidual');
  const canvas2 = document.getElementById('slrResidualCanvas');
  if (canvas2) {
    const ctx2 = canvas2.getContext('2d');
    charts['slrResidual'] = new Chart(ctx2, {
      type: 'scatter',
      data: {
        datasets: [
          {
            label: 'Residuals (e_i = y_i - ŷ_i)',
            data: reg.residual_points,
            backgroundColor: 'rgba(183, 123, 97, 0.65)',
            borderColor: '#B77B61',
            pointRadius: 3
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'top', labels: { boxWidth: 12 } }
        },
        scales: {
          x: { title: { display: true, text: reg.x_col } },
          y: {
            title: { display: true, text: 'Residual Value' },
            grid: {
              color: function(context) {
                if (context.tick.value === 0) return '#403747';
                return 'rgba(228, 225, 216, 0.7)';
              }
            }
          }
        }
      }
    });
  }
}

async function loadMultipleRegression() {
  const target = document.getElementById('mlr-target-select')?.value || 'entropy';
  const preds = ['query_length'];
  if (document.getElementById('mlr-pred-iat')?.checked) preds.push('inter_arrival_time');
  if (document.getElementById('mlr-pred-freq')?.checked) preds.push('query_frequency');

  try {
    const res = await fetch('/api/stats/regression/multiple', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        y_col: target,
        x_cols: preds
      })
    });
    const data = await res.json();
    if (data.status !== 'success') return;

    const mlr = data.multiple_regression;
    setElText('mlr-r2', `${(mlr.r_squared * 100).toFixed(1)}%`);
    setElText('mlr-adj-r2', `${(mlr.adjusted_r_squared * 100).toFixed(1)}%`);
    setElText('mlr-rmse', mlr.rmse);
    setElText('mlr-interpretation-text', `${mlr.equation} | ${mlr.interpretation}`);

    // Populate Coefficients Table
    const tbody = document.getElementById('mlr-coefficients-tbody');
    if (tbody && mlr.coefficients) {
      tbody.innerHTML = mlr.coefficients.map(c => `
        <tr>
          <td><strong>${c.term}</strong></td>
          <td class="numeric"><strong>${c.coefficient}</strong></td>
          <td class="numeric">${c.std_error}</td>
          <td class="numeric">${c.t_statistic}</td>
          <td class="numeric">${c.p_value < 0.0001 ? '< 0.0001' : c.p_value.toFixed(4)}</td>
        </tr>
      `).join('');
    }

    renderMLRCharts(mlr);
  } catch (err) {
    console.error("Failed to load multiple regression:", err);
  }
}

function renderMLRCharts(mlr) {
  // Actual vs Predicted
  destroyChart('mlrActualPred');
  const canvas1 = document.getElementById('mlrActualVsPredCanvas');
  if (canvas1 && mlr.actual_vs_pred) {
    const ctx1 = canvas1.getContext('2d');
    const pts = mlr.actual_vs_pred.map(p => ({ x: p.predicted, y: p.actual }));
    charts['mlrActualPred'] = new Chart(ctx1, {
      type: 'scatter',
      data: {
        datasets: [{
          label: 'Observed vs Fitted',
          data: pts,
          backgroundColor: 'rgba(102, 124, 105, 0.65)',
          borderColor: '#667C69',
          pointRadius: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { title: { display: true, text: 'Predicted ŷ' } },
          y: { title: { display: true, text: 'Actual y' } }
        }
      }
    });
  }

  // Residuals vs Fitted
  destroyChart('mlrResiduals');
  const canvas2 = document.getElementById('mlrResidualsCanvas');
  if (canvas2 && mlr.residuals_plot) {
    const ctx2 = canvas2.getContext('2d');
    const pts2 = mlr.residuals_plot.map(p => ({ x: p.predicted, y: p.residual }));
    charts['mlrResiduals'] = new Chart(ctx2, {
      type: 'scatter',
      data: {
        datasets: [{
          label: 'Residuals vs Fitted',
          data: pts2,
          backgroundColor: 'rgba(64, 55, 71, 0.65)',
          borderColor: '#403747',
          pointRadius: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          x: { title: { display: true, text: 'Fitted Value ŷ' } },
          y: { title: { display: true, text: 'Residual (y - ŷ)' } }
        }
      }
    });
  }
}

// =====================================================================
// 6. Hypothesis Testing Section Controller
// =====================================================================

async function loadHypothesisData() {
  const feat = document.getElementById('ht-feature-select')?.value || 'query_length';
  const confLevel = parseFloat(document.getElementById('ci-level-select')?.value || '0.95');
  const ciGroup = document.getElementById('ci-group-select')?.value || 'Overall';

  try {
    const res = await fetch(`/api/stats/hypothesis?feature=${feat}&confidence_level=${confLevel}&ci_group=${ciGroup}`);
    const data = await res.json();
    if (data.status !== 'success') return;

    // Populate Two-Sample t-Tests Table
    const tbody = document.getElementById('ht-t-test-tbody');
    if (tbody && data.two_sample_t_tests) {
      tbody.innerHTML = Object.keys(data.two_sample_t_tests).map(k => {
        const t = data.two_sample_t_tests[k];
        const verdict = t.reject_h0_alpha_05 ? 'Reject H₀ (p < 0.05)' : 'Fail to Reject H₀';
        const badge = t.reject_h0_alpha_05 ? 'badge-suspicious' : 'badge-normal';
        return `
          <tr>
            <td><strong>${t.feature}</strong></td>
            <td class="numeric">${t.group1.mean}</td>
            <td class="numeric">${t.group2.mean}</td>
            <td class="numeric">${t.mean_difference}</td>
            <td class="numeric"><strong>${t.t_statistic}</strong></td>
            <td class="numeric">${t.degrees_of_freedom}</td>
            <td class="numeric">${t.p_value < 0.0001 ? '< 0.0001' : t.p_value.toFixed(4)}</td>
            <td class="numeric">${t.cohens_d} (${t.effect_size_label})</td>
            <td><span class="badge ${badge}">${verdict}</span></td>
          </tr>
        `;
      }).join('');
    }

    // Selected Feature Verdict Box
    const selectedTest = data.selected_feature_test;
    if (selectedTest && selectedTest.conclusion) {
      setElText('ht-verdict-box', selectedTest.conclusion);
    }

    // Confidence Interval Analysis Card
    const ciData = data.confidence_interval_analysis?.details;
    if (ciData && ciData.selected_ci) {
      const sel = ciData.selected_ci;
      setElText('ci-card-mean', ciData.sample_mean);
      setElText('ci-card-margin', `± ${sel.margin_of_error}`);
      setElText('ci-card-interval', `[ ${sel.lower_bound} , ${sel.upper_bound} ]`);
      setElText('ci-interpretation-box', `
        We are ${parseInt(sel.confidence_level * 100)}% confident that the true population mean of ${feat}
        for ${ciGroup} traffic lies within the interval [${sel.lower_bound}, ${sel.upper_bound}]
        (Sample n = ${ciData.n}, Standard Error = ${ciData.standard_error}, Critical t* = ${sel.t_critical}).
      `);
    }
  } catch (err) {
    console.error("Failed to load hypothesis testing:", err);
  }
}

// =====================================================================
// 7. Statistical Anomaly Detection Controller
// =====================================================================

async function loadAnomalyData() {
  const feat = document.getElementById('ad-feature-select')?.value || 'query_length';
  const zThresh = parseFloat(document.getElementById('ad-z-thresh')?.value || '2.5');
  const iqrMult = parseFloat(document.getElementById('ad-iqr-mult')?.value || '1.5');

  try {
    const res = await fetch(`/api/stats/anomaly?feature=${feat}&z_threshold=${zThresh}&iqr_multiplier=${iqrMult}`);
    const data = await res.json();
    if (data.status !== 'success') return;

    const ad = data.anomaly_analysis;

    // Badges & Cutoffs
    setElText('ad-z-cutoffs-badge', ad.z_score_method.cutoffs);
    setElText('ad-iqr-bounds-badge', `Bounds: ${ad.iqr_method.bounds}`);

    // Numbers
    setElText('ad-z-total', `${ad.z_score_method.outliers_count} (${ad.z_score_method.outliers_pct}%)`);
    setElText('ad-z-normal', ad.z_score_method.normal_outliers);
    setElText('ad-z-susp', ad.z_score_method.suspicious_outliers);

    setElText('ad-iqr-total', `${ad.iqr_method.outliers_count} (${ad.iqr_method.outliers_pct}%)`);
    setElText('ad-iqr-normal', ad.iqr_method.normal_outliers);
    setElText('ad-iqr-susp', ad.iqr_method.suspicious_outliers);

    // Flagged Sample Records Table
    const tbody = document.getElementById('ad-flagged-tbody');
    if (tbody && ad.flagged_sample) {
      if (ad.flagged_sample.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:18px; color:var(--text-secondary);">No outliers detected at current threshold parameters.</td></tr>`;
      } else {
        tbody.innerHTML = ad.flagged_sample.map(r => `
          <tr>
            <td>${r.timestamp}</td>
            <td><code style="font-size:0.8rem; font-family:var(--font-mono);">${r.query}</code></td>
            <td class="numeric">${r.feature_value}</td>
            <td class="numeric">${r.z_score}</td>
            <td>${r.z_flagged ? '<span class="badge badge-suspicious">Outlier</span>' : '<span class="badge badge-info">Within Bounds</span>'}</td>
            <td>${r.iqr_flagged ? '<span class="badge badge-suspicious">Outlier</span>' : '<span class="badge badge-info">Within Bounds</span>'}</td>
            <td><span class="badge ${r.label === 'Suspicious' ? 'badge-suspicious' : 'badge-normal'}">${r.label}</span></td>
          </tr>
        `).join('');
      }
    }

    setElText('ad-interpretation-text', ad.interpretation);
  } catch (err) {
    console.error("Failed to load anomaly detection:", err);
  }
}

// =====================================================================
// 8. Detection Results Controller
// =====================================================================

async function loadDetectionResults() {
  const lenThresh = parseInt(document.getElementById('det-len-thresh')?.value || '40');
  const iatThresh = parseFloat(document.getElementById('det-iat-thresh')?.value || '0.30');
  const entThresh = parseFloat(document.getElementById('det-ent-thresh')?.value || '3.75');

  try {
    const res = await fetch('/api/detector/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        length_threshold: lenThresh,
        iat_threshold: iatThresh,
        entropy_threshold: entThresh
      })
    });
    const data = await res.json();
    if (data.status !== 'success') return;

    const b = data.benchmark.detectors;

    // Populate Benchmark Table
    const tbody = document.getElementById('det-benchmark-tbody');
    if (tbody) {
      const list = [
        b.length_only,
        b.timing_only,
        b.entropy_only,
        b.combined
      ].filter(Boolean);

      tbody.innerHTML = list.map(d => {
        const m = d.results.metrics;
        return `
          <tr>
            <td>
              <strong>${d.name}</strong><br>
              <span style="font-size:0.75rem; color:var(--text-secondary);"><code>${d.condition}</code></span>
            </td>
            <td class="numeric"><strong>${m.detection_rate_pct}%</strong></td>
            <td class="numeric" style="color:${m.false_positive_rate_pct > 5 ? 'var(--danger)' : 'var(--text-main)'};">${m.false_positive_rate_pct}%</td>
            <td class="numeric">${m.precision_pct}%</td>
            <td class="numeric"><strong>${m.f1_score.toFixed(3)}</strong></td>
            <td class="numeric">${m.accuracy_pct}%</td>
          </tr>
        `;
      }).join('');
    }

    // 2x2 Confusion Matrix for Combined
    if (b.combined && b.combined.results.confusion_matrix) {
      const cm = b.combined.results.confusion_matrix;
      setElText('cm-tp', cm.tp.toLocaleString());
      setElText('cm-fp', cm.fp.toLocaleString());
      setElText('cm-fn', cm.fn.toLocaleString());
      setElText('cm-tn', cm.tn.toLocaleString());
    }

    setElText('det-distinction-note', data.benchmark.distinction_note || '');
  } catch (err) {
    console.error("Failed to load detection results:", err);
  }
}

// =====================================================================
// 9. Dataset Controls & Upload Modal Handler
// =====================================================================

function initDatasetControls() {
  // Switcher in sidebar
  document.getElementById('sidebar-dataset-select')?.addEventListener('change', async (e) => {
    const filename = e.target.value;
    try {
      const res = await fetch('/api/dataset/switch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename })
      });
      const data = await res.json();
      if (data.status === 'success') {
        state.descriptiveCache = null;
        state.recordsPage = 1;
        await loadOverviewData();
        loadAllDataForActiveTab();
      }
    } catch (err) {
      console.error("Failed to switch dataset:", err);
    }
  });

  // Table Controls
  document.getElementById('table-search')?.addEventListener('input', (e) => {
    state.recordsSearch = e.target.value;
    state.recordsPage = 1;
    loadDatasetRecords();
  });

  document.getElementById('table-label-filter')?.addEventListener('change', (e) => {
    state.recordsLabelFilter = e.target.value;
    state.recordsPage = 1;
    loadDatasetRecords();
  });

  document.getElementById('table-sort-by')?.addEventListener('change', (e) => {
    state.recordsSortBy = e.target.value;
    state.recordsPage = 1;
    loadDatasetRecords();
  });

  document.getElementById('btn-prev-page')?.addEventListener('click', () => {
    if (state.recordsPage > 1) {
      state.recordsPage--;
      loadDatasetRecords();
    }
  });

  document.getElementById('btn-next-page')?.addEventListener('click', () => {
    state.recordsPage++;
    loadDatasetRecords();
  });

  // Descriptive Feature Switcher
  document.getElementById('desc-feature-select')?.addEventListener('change', updateDescriptiveView);

  // Probability Controls
  document.getElementById('prob-normal-feature')?.addEventListener('change', loadProbabilityData);
  document.getElementById('poisson-interval-select')?.addEventListener('change', loadProbabilityData);

  // Correlation Selectors
  document.getElementById('corr-x-select')?.addEventListener('change', loadCorrelationData);
  document.getElementById('corr-y-select')?.addEventListener('change', loadCorrelationData);

  // Regression Fit Buttons
  document.getElementById('btn-run-slr')?.addEventListener('click', loadSimpleRegression);
  document.getElementById('btn-run-mlr')?.addEventListener('click', loadMultipleRegression);

  // Hypothesis Controls
  document.getElementById('ht-feature-select')?.addEventListener('change', loadHypothesisData);
  document.getElementById('btn-recompute-ci')?.addEventListener('click', loadHypothesisData);

  // Anomaly Controls
  document.getElementById('btn-run-anomaly')?.addEventListener('click', loadAnomalyData);
  document.getElementById('ad-feature-select')?.addEventListener('change', loadAnomalyData);

  // Detection Benchmark Button
  document.getElementById('btn-re-eval-detectors')?.addEventListener('click', loadDetectionResults);

  // Modal Handlers
  initUploadModal();
}

function initUploadModal() {
  const modal = document.getElementById('upload-modal');
  const openBtn = document.getElementById('btn-open-upload-modal');
  const closeBtn = document.getElementById('btn-close-upload-modal');
  const cancelBtn = document.getElementById('btn-cancel-upload');
  const dropzone = document.getElementById('upload-dropzone');
  const fileInput = document.getElementById('modal-file-input');
  const submitBtn = document.getElementById('btn-submit-upload');
  const statusBox = document.getElementById('upload-status-box');

  const openModal = () => {
    if (modal) modal.classList.add('active');
    if (statusBox) statusBox.style.display = 'none';
    if (submitBtn) submitBtn.disabled = true;
    state.selectedUploadFile = null;
  };

  const closeModal = () => {
    if (modal) modal.classList.remove('active');
  };

  openBtn?.addEventListener('click', openModal);
  closeBtn?.addEventListener('click', closeModal);
  cancelBtn?.addEventListener('click', closeModal);

  dropzone?.addEventListener('click', () => fileInput?.click());

  dropzone?.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.style.borderColor = 'var(--primary-accent)';
  });

  dropzone?.addEventListener('dragleave', () => {
    dropzone.style.borderColor = 'var(--border-color)';
  });

  dropzone?.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.style.borderColor = 'var(--border-color)';
    if (e.dataTransfer.files.length > 0) {
      handleFileSelected(e.dataTransfer.files[0]);
    }
  });

  fileInput?.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleFileSelected(e.target.files[0]);
    }
  });

  function handleFileSelected(file) {
    if (!file.name.toLowerCase().endswith('.csv') && !file.name.toLowerCase().endsWith('.csv')) {
      showStatus("Please select a valid CSV file (.csv)", true);
      return;
    }
    state.selectedUploadFile = file;
    if (submitBtn) submitBtn.disabled = false;
    showStatus(`Selected: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`, false);
  }

  submitBtn?.addEventListener('click', async () => {
    if (!state.selectedUploadFile) return;

    const formData = new FormData();
    formData.append('file', state.selectedUploadFile);
    submitBtn.disabled = true;
    submitBtn.textContent = 'Uploading...';

    try {
      const res = await fetch('/api/dataset/upload', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (data.status === 'success') {
        showStatus(`Success: ${data.message}`, false);
        state.descriptiveCache = null;
        state.recordsPage = 1;
        setTimeout(() => {
          closeModal();
          loadOverviewData();
          loadAllDataForActiveTab();
          submitBtn.textContent = 'Upload & Analyze';
        }, 800);
      } else {
        showStatus(`Upload Error: ${data.message}`, true);
        submitBtn.disabled = false;
        submitBtn.textContent = 'Upload & Analyze';
      }
    } catch (err) {
      showStatus(`Network Error: ${err.message}`, true);
      submitBtn.disabled = false;
      submitBtn.textContent = 'Upload & Analyze';
    }
  });

  function showStatus(msg, isError) {
    if (!statusBox) return;
    statusBox.style.display = 'block';
    statusBox.style.backgroundColor = isError ? 'var(--danger-bg)' : 'var(--success-bg)';
    statusBox.style.color = isError ? 'var(--danger)' : 'var(--success)';
    statusBox.style.border = `1px solid ${isError ? '#eccbc0' : '#d1ded3'}`;
    statusBox.textContent = msg;
  }
}

// Helpers
function setElText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text !== null && text !== undefined ? text : '-';
}

function setElHtml(id, html) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = html;
}

// Global Initialization on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  initNavigation();
  initDatasetControls();
  loadOverviewData();
});
