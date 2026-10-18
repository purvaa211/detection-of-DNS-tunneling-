/**
 * Main Frontend Application Script
 * Probability and Statistics DNS Tunneling Project
 */

// Global Chart Instances to avoid canvas re-use errors
const charts = {};

function destroyChart(name) {
  if (charts[name]) {
    charts[name].destroy();
    delete charts[name];
  }
}

// State
let currentPage = 1;
const pageSize = 12;
let currentSort = 'timestamp';
let currentSortOrder = 'asc';

// Tab switching logic
function initTabs() {
  const tabButtons = document.querySelectorAll('.nav-tab-btn');
  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      btn.classList.add('active');
      const targetId = btn.getAttribute('data-tab');
      const targetContent = document.getElementById(targetId);
      if (targetContent) {
        targetContent.classList.add('active');
      }

      // Trigger module-specific loads if first time
      onTabActivated(targetId);
    });
  });
}

function onTabActivated(tabId) {
  if (tabId === 'tab-descriptive') {
    loadDescriptiveStats();
  } else if (tabId === 'tab-probability') {
    loadProbabilityModels();
  } else if (tabId === 'tab-sampling') {
    loadSamplingCLT();
  } else if (tabId === 'tab-hypothesis') {
    loadHypothesisTests();
  } else if (tabId === 'tab-regression') {
    loadRegression();
  } else if (tabId === 'tab-detector') {
    loadDetectorBenchmark();
  }
}

// -------------------------------------------------------------
// 1. Overview & Dataset Operations
// -------------------------------------------------------------

async function loadDatasetInfo() {
  try {
    const res = await fetch('/api/dataset/info');
    const data = await res.json();
    if (data.status !== 'success') return;

    document.getElementById('metric-total-queries').textContent = data.total_queries.toLocaleString();
    document.getElementById('metric-normal-queries').textContent = `${data.normal_queries.toLocaleString()} (${data.normal_pct}%)`;
    document.getElementById('metric-suspicious-queries').textContent = `${data.suspicious_queries.toLocaleString()} (${data.suspicious_pct}%)`;
    document.getElementById('metric-mean-entropy').textContent = `${data.mean_entropy} bits`;
    document.getElementById('metric-mean-length').textContent = `${data.mean_length} chars`;
    document.getElementById('metric-mean-iat').textContent = `${data.mean_iat_seconds} s`;

    // Populate dataset selector
    const selector = document.getElementById('dataset-select');
    selector.innerHTML = '';
    data.available_datasets.forEach(name => {
      const opt = document.createElement('option');
      opt.value = name;
      opt.textContent = name;
      if (name === data.dataset_name) opt.selected = true;
      selector.appendChild(opt);
    });

    loadDatasetRecords();
  } catch (err) {
    console.error("Failed to load dataset info:", err);
  }
}

async function loadDatasetRecords() {
  const search = document.getElementById('table-search')?.value || '';
  const label = document.getElementById('table-label-filter')?.value || 'all';

  const params = new URLSearchParams({
    page: currentPage,
    page_size: pageSize,
    search: search,
    label: label,
    sort_by: currentSort,
    sort_order: currentSortOrder
  });

  try {
    const res = await fetch(`/api/dataset/records?${params.toString()}`);
    const data = await res.json();
    if (data.status !== 'success') return;

    const tbody = document.getElementById('dns-records-tbody');
    tbody.innerHTML = '';

    if (data.records.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 20px; color: #64748b;">No matching DNS queries found.</td></tr>`;
    } else {
      data.records.forEach(row => {
        const tr = document.createElement('tr');
        const badgeClass = row.label === 'Suspicious' ? 'badge-suspicious' : 'badge-normal';
        tr.innerHTML = `
          <td>${row.timestamp}</td>
          <td><code style="font-size: 0.82rem; word-break: break-all;">${row.query}</code></td>
          <td><span class="badge badge-info">${row.record_type}</span></td>
          <td class="numeric">${row.query_length}</td>
          <td class="numeric">${row.entropy.toFixed(4)}</td>
          <td class="numeric">${row.inter_arrival_time.toFixed(4)}</td>
          <td><span class="badge ${badgeClass}">${row.label}</span></td>
        `;
        tbody.appendChild(tr);
      });
    }

    // Pagination info
    document.getElementById('page-info').textContent = `Page ${data.page} of ${data.total_pages} (${data.total_records} records)`;
    document.getElementById('btn-prev-page').disabled = (data.page <= 1);
    document.getElementById('btn-next-page').disabled = (data.page >= data.total_pages);
  } catch (err) {
    console.error("Failed to load records:", err);
  }
}

function initDatasetControls() {
  const selector = document.getElementById('dataset-select');
  selector.addEventListener('change', async (e) => {
    const filename = e.target.value;
    const res = await fetch('/api/dataset/switch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename })
    });
    const data = await res.json();
    if (data.status === 'success') {
      currentPage = 1;
      await loadDatasetInfo();
      // Reload active tab
      const activeBtn = document.querySelector('.nav-tab-btn.active');
      if (activeBtn) onTabActivated(activeBtn.getAttribute('data-tab'));
    }
  });

  // Search and filter
  document.getElementById('table-search')?.addEventListener('input', () => {
    currentPage = 1;
    loadDatasetRecords();
  });

  document.getElementById('table-label-filter')?.addEventListener('change', () => {
    currentPage = 1;
    loadDatasetRecords();
  });

  document.getElementById('btn-prev-page')?.addEventListener('click', () => {
    if (currentPage > 1) {
      currentPage--;
      loadDatasetRecords();
    }
  });

  document.getElementById('btn-next-page')?.addEventListener('click', () => {
    currentPage++;
    loadDatasetRecords();
  });

  // Upload handler
  const uploadForm = document.getElementById('upload-form');
  const uploadFile = document.getElementById('upload-file');
  const uploadStatus = document.getElementById('upload-status');

  uploadForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!uploadFile.files || uploadFile.files.length === 0) return;

    const formData = new FormData();
    formData.append('file', uploadFile.files[0]);

    uploadStatus.textContent = 'Processing dataset and computing features...';
    try {
      const res = await fetch('/api/dataset/upload', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (data.status === 'success') {
        uploadStatus.textContent = `Uploaded and processed: ${data.dataset_name} (${data.rows} rows)`;
        uploadStatus.style.color = 'var(--normal-color)';
        currentPage = 1;
        await loadDatasetInfo();
      } else {
        uploadStatus.textContent = `Error: ${data.message}`;
        uploadStatus.style.color = 'var(--suspicious-color)';
      }
    } catch (err) {
      uploadStatus.textContent = 'Upload failed. Please check CSV format.';
      uploadStatus.style.color = 'var(--suspicious-color)';
    }
  });
}

// -------------------------------------------------------------
// 2. Descriptive Statistics
// -------------------------------------------------------------

let descriptiveDataCache = null;

async function loadDescriptiveStats() {
  try {
    const res = await fetch('/api/stats/descriptive');
    const data = await res.json();
    if (data.status !== 'success') return;
    descriptiveDataCache = data.features;

    updateDescriptiveView();
  } catch (err) {
    console.error("Failed to load descriptive stats:", err);
  }
}

function updateDescriptiveView() {
  if (!descriptiveDataCache) return;
  const feat = document.getElementById('desc-feature-select').value;
  const featData = descriptiveDataCache[feat];
  if (!featData) return;

  const normal = featData.descriptive.normal;
  const suspicious = featData.descriptive.suspicious;
  const overall = featData.descriptive.overall;

  const rows = [
    { label: "Sample Size (n)", n: normal.n, s: suspicious.n, o: overall.n, format: v => v },
    { label: "Mean (μ / x̄)", n: normal.mean, s: suspicious.mean, o: overall.mean, format: v => v.toFixed(4) },
    { label: "Median (Q2)", n: normal.median, s: suspicious.median, o: overall.median, format: v => v.toFixed(4) },
    { label: "Mode", n: normal.mode, s: suspicious.mode, o: overall.mode, format: v => v.toFixed(4) },
    { label: "Sample Variance (s²)", n: normal.sample_variance, s: suspicious.sample_variance, o: overall.sample_variance, format: v => v.toFixed(4) },
    { label: "Sample Std Dev (s)", n: normal.sample_std, s: suspicious.sample_std, o: overall.sample_std, format: v => v.toFixed(4) },
    { label: "Standard Error (SE = s/√n)", n: normal.standard_error, s: suspicious.standard_error, o: overall.standard_error, format: v => v.toFixed(4) },
    { label: "Coeff. of Variation (CV %)", n: normal.coefficient_of_variation_pct, s: suspicious.coefficient_of_variation_pct, o: overall.coefficient_of_variation_pct, format: v => v.toFixed(2) + '%' },
    { label: "1st Quartile (Q1)", n: normal.q1, s: suspicious.q1, o: overall.q1, format: v => v.toFixed(4) },
    { label: "3rd Quartile (Q3)", n: normal.q3, s: suspicious.q3, o: overall.q3, format: v => v.toFixed(4) },
    { label: "Interquartile Range (IQR)", n: normal.iqr, s: suspicious.iqr, o: overall.iqr, format: v => v.toFixed(4) },
    { label: "Min / Max / Range", n: `${normal.min} / ${normal.max}`, s: `${suspicious.min} / ${suspicious.max}`, o: `${overall.min} / ${overall.max}`, format: v => v },
    { label: "Skewness", n: normal.skewness, s: suspicious.skewness, o: overall.skewness, format: v => v.toFixed(4) },
    { label: "Kurtosis (Excess)", n: normal.kurtosis, s: suspicious.kurtosis, o: overall.kurtosis, format: v => v.toFixed(4) }
  ];

  const tbody = document.getElementById('desc-stats-tbody');
  tbody.innerHTML = '';
  rows.forEach(r => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${r.label}</strong></td>
      <td class="numeric">${r.format(r.n)}</td>
      <td class="numeric">${r.format(r.s)}</td>
      <td class="numeric">${r.format(r.o)}</td>
    `;
    tbody.appendChild(tr);
  });

  // Render Histogram
  renderHistogramChart(feat, featData.histograms);

  // Update plain-English explanation
  const diffPct = (((suspicious.mean - normal.mean) / normal.mean) * 100).toFixed(1);
  const featName = feat === 'entropy' ? 'Shannon Entropy' : feat === 'query_length' ? 'Query Length' : 'Inter-Arrival Time';
  const unit = feat === 'entropy' ? 'bits/char' : feat === 'query_length' ? 'characters' : 'seconds';

  document.getElementById('desc-interpretation-text').innerHTML = `
    <strong>Statistical Takeaway for ${featName}:</strong><br>
    • <strong>Mean Difference:</strong> Normal traffic averages <code>${normal.mean} ${unit}</code> (std: ${normal.sample_std}), whereas Suspicious/Tunneling traffic averages <code>${suspicious.mean} ${unit}</code> (std: ${suspicious.sample_std}), representing a <strong>${Math.abs(diffPct)}% ${diffPct >= 0 ? 'increase' : 'decrease'}</strong>.<br>
    • <strong>Dispersion (CV):</strong> Normal CV is <code>${normal.coefficient_of_variation_pct}%</code> vs Suspicious CV <code>${suspicious.coefficient_of_variation_pct}%</code>. Lower CV indicates tighter clustering.<br>
    • <strong>Skewness:</strong> Normal skewness is <code>${normal.skewness}</code> (${normal.skewness > 0 ? 'right-skewed' : 'left-skewed'}), while Suspicious skewness is <code>${suspicious.skewness}</code>.
  `;
}

function renderHistogramChart(feature, histograms) {
  destroyChart('descHistogram');
  const ctx = document.getElementById('descHistogramChart').getContext('2d');

  const normHist = histograms.normal;
  const suspHist = histograms.suspicious;

  // Use common bin labels
  const labels = normHist.labels.length >= suspHist.labels.length ? normHist.labels : suspHist.labels;

  charts['descHistogram'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Normal Traffic (Frequency)',
          data: normHist.counts,
          backgroundColor: 'rgba(16, 185, 129, 0.65)',
          borderColor: '#059669',
          borderWidth: 1
        },
        {
          label: 'Suspicious / Tunneling (Frequency)',
          data: suspHist.counts,
          backgroundColor: 'rgba(239, 68, 68, 0.65)',
          borderColor: '#dc2626',
          borderWidth: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: 'top' },
        tooltip: { mode: 'index', intersect: false }
      },
      scales: {
        x: {
          title: { display: true, text: `${feature.replace('_', ' ').toUpperCase()} Bins` }
        },
        y: {
          title: { display: true, text: 'Query Count (Frequency)' },
          beginAtZero: true
        }
      }
    }
  });
}

// -------------------------------------------------------------
// 3. Probability & Distributions
// -------------------------------------------------------------

async function loadProbabilityModels() {
  const prior = parseFloat(document.getElementById('bayes-prior-slider').value);
  const sens = parseFloat(document.getElementById('bayes-sens-slider').value);
  const fpr = parseFloat(document.getElementById('bayes-fpr-slider').value);

  const nBatch = parseInt(document.getElementById('binom-n-slider').value);
  const pBatch = parseFloat(document.getElementById('binom-p-slider').value);

  try {
    const res = await fetch('/api/stats/probability', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prior_tunnel: prior,
        sensitivity: sens,
        fpr: fpr,
        n_batch: nBatch,
        p_batch: pBatch
      })
    });
    const data = await res.json();
    if (data.status !== 'success') return;

    // 1. Bayes' Theorem UI
    const bayes = data.bayes_theorem;
    document.getElementById('bayes-posterior-val').textContent = `${bayes.posterior_pct}%`;
    document.getElementById('bayes-marginal-val').textContent = `${(bayes.marginal_p_alarm * 100).toFixed(2)}%`;
    document.getElementById('bayes-npv-val').textContent = `${(bayes.posterior_normal_given_no_alarm * 100).toFixed(2)}%`;
    document.getElementById('bayes-note-text').textContent = bayes.base_rate_fallacy_note;

    // 2. Binomial Distribution Chart
    const binom = data.binomial_batch;
    document.getElementById('binom-mean-val').textContent = `E[X] = ${binom.mean}`;
    document.getElementById('binom-var-val').textContent = `Var(X) = ${binom.variance} (σ = ${binom.std_dev})`;
    renderBinomialChart(binom);

    // 3. Poisson Arrival Chart
    renderPoissonChart(data.poisson_process);

    // 4. Exponential IAT Chart
    renderExponentialChart(data.exponential_iat);
  } catch (err) {
    console.error("Failed to load probability models:", err);
  }
}

function renderBinomialChart(binom) {
  destroyChart('binomialChart');
  const ctx = document.getElementById('binomialChartCanvas').getContext('2d');

  charts['binomialChart'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: binom.k_values,
      datasets: [
        {
          type: 'bar',
          label: 'P(X = k) [PMF]',
          data: binom.pmf,
          backgroundColor: 'rgba(59, 130, 246, 0.65)',
          borderColor: '#2563eb',
          borderWidth: 1,
          yAxisID: 'y'
        },
        {
          type: 'line',
          label: 'P(X ≤ k) [CDF]',
          data: binom.cdf,
          borderColor: '#f59e0b',
          backgroundColor: '#f59e0b',
          borderWidth: 2,
          pointRadius: 2,
          yAxisID: 'y1'
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { title: { display: true, text: 'Number of Tunneling Queries (k) in batch n' } },
        y: { title: { display: true, text: 'Probability P(X = k)' }, beginAtZero: true, max: 1.0 },
        y1: { position: 'right', title: { display: true, text: 'Cumulative P(X ≤ k)' }, beginAtZero: true, max: 1.0, grid: { drawOnChartArea: false } }
      }
    }
  });
}

function renderPoissonChart(poisson) {
  if (!poisson || !poisson.k_vals) return;
  destroyChart('poissonChart');
  const ctx = document.getElementById('poissonChartCanvas').getContext('2d');

  document.getElementById('poisson-vmr-text').innerHTML = `
    <strong>Poisson Arrival Modeling:</strong><br>
    Estimated arrival rate: <code>λ = ${poisson.estimated_lambda} arrivals / ${poisson.time_bucket_seconds}s bucket</code>. 
    Index of Dispersion (Variance/Mean Ratio): <code>${poisson.dispersion_ratio_vmr}</code>.<br>
    <em>${poisson.interpretation}</em>
  `;

  charts['poissonChart'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: poisson.k_vals,
      datasets: [
        {
          label: 'Observed Empirical Frequency',
          data: poisson.empirical_frequencies,
          backgroundColor: 'rgba(100, 116, 139, 0.6)',
          borderColor: '#475569',
          borderWidth: 1
        },
        {
          type: 'line',
          label: 'Theoretical Poisson PMF',
          data: poisson.theoretical_poisson,
          borderColor: '#2563eb',
          backgroundColor: '#2563eb',
          borderWidth: 2,
          tension: 0.2
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { title: { display: true, text: 'Arrivals per Time Bucket (k)' } },
        y: { title: { display: true, text: 'Probability' }, beginAtZero: true }
      }
    }
  });
}

function renderExponentialChart(expData) {
  if (!expData || !expData.Normal) return;
  destroyChart('exponentialChart');
  const ctx = document.getElementById('exponentialChartCanvas').getContext('2d');

  const norm = expData.Normal;
  const susp = expData.Suspicious;

  charts['exponentialChart'] = new Chart(ctx, {
    type: 'line',
    data: {
      labels: norm.midpoints,
      datasets: [
        {
          label: 'Normal IAT (Empirical)',
          data: norm.empirical,
          borderColor: '#059669',
          borderWidth: 2,
          tension: 0.2
        },
        {
          label: 'Normal Fitted Exponential PDF',
          data: norm.theoretical_exponential,
          borderColor: '#059669',
          borderDash: [5, 5],
          borderWidth: 2,
          pointRadius: 0
        },
        ...(susp ? [
          {
            label: 'Suspicious IAT (Empirical)',
            data: susp.empirical,
            borderColor: '#dc2626',
            borderWidth: 2,
            tension: 0.2
          }
        ] : [])
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { title: { display: true, text: 'Inter-Arrival Time (seconds)' } },
        y: { title: { display: true, text: 'Relative Frequency / PDF' }, beginAtZero: true }
      }
    }
  });
}

// -------------------------------------------------------------
// 4. Sampling & Central Limit Theorem
// -------------------------------------------------------------

async function loadSamplingCLT() {
  const feat = document.getElementById('clt-feature-select').value;
  const sampleN = parseInt(document.getElementById('clt-n-slider').value);
  const numSamplesN = parseInt(document.getElementById('clt-reps-slider').value);

  try {
    const res = await fetch('/api/stats/sampling', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        feature: feat,
        sample_size_n: sampleN,
        num_samples_N: numSamplesN
      })
    });
    const data = await res.json();
    if (data.status !== 'success') return;

    // Render CLT Histogram
    renderCLTHistogram(data.clt_simulation);

    // Update CLT Stats Callout
    const sim = data.clt_simulation;
    document.getElementById('clt-stats-box').innerHTML = `
      <strong>Central Limit Theorem Simulation Results (N = ${sim.num_samples_N} repeated samples of size n = ${sim.sample_size_n}):</strong><br>
      • Population Mean (μ): <code>${sim.population_mean}</code> | Empirical Mean of Means: <code>${sim.empirical_mean_of_means}</code><br>
      • Theoretical Standard Error (σ / √n): <code>${sim.theoretical_standard_error}</code> | Empirical SE (s_x̄): <code>${sim.empirical_standard_error}</code><br>
      <em>${sim.clt_conclusion}</em>
    `;

    // Confidence Intervals Table
    const ciTableBody = document.getElementById('ci-tbody');
    ciTableBody.innerHTML = '';
    const cis = data.confidence_intervals.confidence_intervals;
    Object.keys(cis).forEach(key => {
      const item = cis[key];
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${key}</strong></td>
        <td class="numeric">${item.t_critical}</td>
        <td class="numeric">±${item.margin_of_error}</td>
        <td class="numeric">[${item.lower_bound}, ${item.upper_bound}]</td>
        <td><small>${item.interpretation}</small></td>
      `;
      ciTableBody.appendChild(tr);
    });

    // Z-Score Normality Test Card
    const zscore = data.zscore_and_normality;
    document.getElementById('normality-box').innerHTML = `
      <strong>Empirical Rule & Normality Check for ${zscore.feature.toUpperCase()}:</strong><br>
      • Within ±1σ: <code>${zscore.empirical_rule.within_1_sigma_pct}%</code> (Theoretical: 68.27%)<br>
      • Within ±2σ: <code>${zscore.empirical_rule.within_2_sigma_pct}%</code> (Theoretical: 95.45%)<br>
      • Within ±3σ: <code>${zscore.empirical_rule.within_3_sigma_pct}%</code> (Theoretical: 99.73%)<br>
      • Extreme Outliers (|Z| > 3): <code>${zscore.outliers_count_abs_z_gt_3}</code> queries<br>
      • D'Agostino-Pearson Test: <code>p-value = ${zscore.dagostino_p_value.toExponential(4)}</code>. <em>${zscore.interpretation}</em>
    `;
  } catch (err) {
    console.error("Failed to load CLT:", err);
  }
}

function renderCLTHistogram(clt) {
  destroyChart('cltChart');
  const ctx = document.getElementById('cltChartCanvas').getContext('2d');
  const hist = clt.clt_histogram;

  charts['cltChart'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: hist.labels,
      datasets: [
        {
          type: 'bar',
          label: `Sample Means Frequency (n = ${clt.sample_size_n})`,
          data: hist.relative_frequencies,
          backgroundColor: 'rgba(59, 130, 246, 0.6)',
          borderColor: '#2563eb',
          borderWidth: 1
        },
        {
          type: 'line',
          label: 'Theoretical Normal Bell Curve N(μ, σ²/n)',
          data: hist.theoretical_normal_curve,
          borderColor: '#dc2626',
          borderWidth: 2,
          pointRadius: 2,
          tension: 0.3
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { title: { display: true, text: 'Sample Mean Values (x̄)' } },
        y: { title: { display: true, text: 'Relative Frequency' }, beginAtZero: true }
      }
    }
  });
}

// -------------------------------------------------------------
// 5. Hypothesis Testing & ANOVA
// -------------------------------------------------------------

async function loadHypothesisTests() {
  try {
    const res = await fetch('/api/stats/hypothesis');
    const data = await res.json();
    if (data.status !== 'success') return;

    // Two-Sample t-tests
    const ttests = data.two_sample_t_tests;
    const tBody = document.getElementById('t-test-tbody');
    tBody.innerHTML = '';

    ['entropy', 'query_length', 'inter_arrival_time'].forEach(feat => {
      const t = ttests[feat];
      const tr = document.createElement('tr');
      const badgeClass = t.reject_h0_alpha_05 ? 'badge-suspicious' : 'badge-normal';
      const verdict = t.reject_h0_alpha_05 ? 'Reject H0 (p < 0.05)' : 'Fail to Reject H0';

      tr.innerHTML = `
        <td><strong>${t.feature}</strong></td>
        <td class="numeric">${t.group1.mean}</td>
        <td class="numeric">${t.group2.mean}</td>
        <td class="numeric">${t.t_statistic}</td>
        <td class="numeric">${t.degrees_of_freedom}</td>
        <td class="numeric">${t.p_value.toExponential(4)}</td>
        <td class="numeric">${t.cohens_d}</td>
        <td><span class="badge ${badgeClass}">${verdict}</span></td>
      `;
      tBody.appendChild(tr);
    });

    // Chi-Square Test
    const chi = data.chi_square_test;
    const chiObsBody = document.getElementById('chi-observed-tbody');
    chiObsBody.innerHTML = '';
    chi.categories.forEach((cat, idx) => {
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td><strong>${cat}</strong></td>
        <td class="numeric">${chi.observed.Normal[idx]} (Exp: ${chi.expected.Normal[idx]})</td>
        <td class="numeric">${chi.observed.Suspicious[idx]} (Exp: ${chi.expected.Suspicious[idx]})</td>
      `;
      chiObsBody.appendChild(tr);
    });

    document.getElementById('chi-stat-val').textContent = `χ² = ${chi.chi2_statistic} (df = ${chi.degrees_of_freedom}, p = ${chi.p_value.toExponential(4)})`;
    document.getElementById('chi-conclusion-text').textContent = chi.conclusion;

    // ANOVA Test
    const anova = data.one_way_anova.entropy_by_record_type;
    const anovaBody = document.getElementById('anova-tbody');
    anovaBody.innerHTML = `
      <tr>
        <td><strong>Between Groups (Record Types)</strong></td>
        <td class="numeric">${anova.ss_between}</td>
        <td class="numeric">${anova.df_between}</td>
        <td class="numeric">${anova.ms_between}</td>
        <td class="numeric" rowspan="2"><strong>${anova.f_statistic}</strong></td>
        <td class="numeric" rowspan="2"><strong>${anova.p_value.toExponential(4)}</strong></td>
      </tr>
      <tr>
        <td><strong>Within Groups (Residuals)</strong></td>
        <td class="numeric">${anova.ss_within}</td>
        <td class="numeric">${anova.df_within}</td>
        <td class="numeric">${anova.ms_within}</td>
      </tr>
      <tr>
        <td><strong>Total</strong></td>
        <td class="numeric">${anova.ss_total}</td>
        <td class="numeric">${anova.df_between + anova.df_within}</td>
        <td class="numeric">-</td>
        <td class="numeric">-</td>
        <td class="numeric">-</td>
      </tr>
    `;
    document.getElementById('anova-conclusion-text').textContent = anova.conclusion;

  } catch (err) {
    console.error("Failed to load hypothesis tests:", err);
  }
}

// -------------------------------------------------------------
// 6. Correlation & Linear Regression
// -------------------------------------------------------------

async function loadRegression() {
  try {
    const res = await fetch('/api/stats/regression');
    const data = await res.json();
    if (data.status !== 'success') return;

    const reg = data.regression;
    document.getElementById('reg-pearson-r').textContent = reg.pearson_r;
    document.getElementById('reg-spearman-rho').textContent = reg.spearman_rho;
    document.getElementById('reg-r2').textContent = `${(reg.r_squared * 100).toFixed(1)}% (${reg.r_squared})`;
    document.getElementById('reg-equation').textContent = `Entropy = ${reg.intercept} + (${reg.slope} × QueryLength)`;
    document.getElementById('reg-interpretation-text').textContent = reg.interpretation;

    renderRegressionChart(reg);
  } catch (err) {
    console.error("Failed to load regression:", err);
  }
}

function renderRegressionChart(reg) {
  destroyChart('regressionChart');
  const ctx = document.getElementById('regressionChartCanvas').getContext('2d');

  charts['regressionChart'] = new Chart(ctx, {
    type: 'scatter',
    data: {
      datasets: [
        {
          label: 'DNS Queries (Sample)',
          data: reg.scatter_points,
          backgroundColor: 'rgba(59, 130, 246, 0.45)',
          borderColor: '#2563eb',
          pointRadius: 3
        },
        {
          type: 'line',
          label: `OLS Fitted Line: y = ${reg.intercept} + ${reg.slope}x`,
          data: reg.regression_line,
          borderColor: '#dc2626',
          borderWidth: 2,
          pointRadius: 0,
          fill: false
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { title: { display: true, text: 'Query Length (Characters)' } },
        y: { title: { display: true, text: 'Shannon Entropy (bits/char)' }, min: 1.0, max: 6.0 }
      }
    }
  });
}

// -------------------------------------------------------------
// 7. Statistical Detection Module & Benchmark
// -------------------------------------------------------------

async function loadDetectorBenchmark() {
  const entropyThresh = parseFloat(document.getElementById('det-entropy-slider').value);
  const iatThresh = parseFloat(document.getElementById('det-iat-slider').value);
  const lenThresh = parseInt(document.getElementById('det-len-slider').value);

  try {
    const res = await fetch('/api/detector/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        entropy_threshold: entropyThresh,
        iat_threshold: iatThresh,
        length_threshold: lenThresh
      })
    });
    const data = await res.json();
    if (data.status !== 'success') return;

    const b = data.benchmark.detectors;

    // Update Confusion Matrices
    renderConfusionMatrix('entropy', b.entropy_only.results.confusion_matrix);
    renderConfusionMatrix('timing', b.timing_only.results.confusion_matrix);
    renderConfusionMatrix('combined', b.combined.results.confusion_matrix);

    // Update Benchmark Metrics Table
    renderDetectorMetricsTable(b);

    // Update Performance Comparison Chart
    renderDetectorComparisonChart(b);

    // Update Comparison Text
    document.getElementById('det-comparison-summary').innerHTML = `
      • <strong>Entropy-Only:</strong> ${data.benchmark.comparisons.entropy_summary}<br>
      • <strong>Timing-Only:</strong> ${data.benchmark.comparisons.timing_summary}<br>
      • <strong>Combined:</strong> ${data.benchmark.comparisons.combined_summary}
    `;
  } catch (err) {
    console.error("Failed to load detector benchmark:", err);
  }
}

function renderConfusionMatrix(prefix, cm) {
  document.getElementById(`cm-${prefix}-tp`).textContent = cm.tp;
  document.getElementById(`cm-${prefix}-fp`).textContent = cm.fp;
  document.getElementById(`cm-${prefix}-fn`).textContent = cm.fn;
  document.getElementById(`cm-${prefix}-tn`).textContent = cm.tn;
}

function renderDetectorMetricsTable(b) {
  const tbody = document.getElementById('det-metrics-tbody');
  tbody.innerHTML = '';

  const list = [
    { name: "1. Shannon Entropy Only", obj: b.entropy_only },
    { name: "2. Timing (IAT) Only", obj: b.timing_only },
    { name: "3. Combined Statistical Detector", obj: b.combined }
  ];

  list.forEach(item => {
    const m = item.obj.results.metrics;
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${item.name}</strong><br><small style="color:var(--text-muted);">${item.obj.condition}</small></td>
      <td class="numeric"><strong>${m.detection_rate_pct}%</strong></td>
      <td class="numeric" style="color: ${m.false_positive_rate_pct > 10 ? 'var(--suspicious-color)' : 'var(--text-main)'};">${m.false_positive_rate_pct}%</td>
      <td class="numeric">${m.precision_pct}%</td>
      <td class="numeric">${m.specificity_pct}%</td>
      <td class="numeric">${m.accuracy_pct}%</td>
      <td class="numeric"><strong>${m.f1_score}</strong></td>
    `;
    tbody.appendChild(tr);
  });
}

function renderDetectorComparisonChart(b) {
  destroyChart('detectorChart');
  const ctx = document.getElementById('detectorComparisonCanvas').getContext('2d');

  charts['detectorChart'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Detection Rate (Sensitivity)', 'False Positive Rate (FPR)', 'Precision (PPV)', 'Accuracy'],
      datasets: [
        {
          label: 'Entropy Only',
          data: [
            b.entropy_only.results.metrics.detection_rate_pct,
            b.entropy_only.results.metrics.false_positive_rate_pct,
            b.entropy_only.results.metrics.precision_pct,
            b.entropy_only.results.metrics.accuracy_pct
          ],
          backgroundColor: 'rgba(59, 130, 246, 0.65)',
          borderColor: '#2563eb',
          borderWidth: 1
        },
        {
          label: 'Timing (IAT) Only',
          data: [
            b.timing_only.results.metrics.detection_rate_pct,
            b.timing_only.results.metrics.false_positive_rate_pct,
            b.timing_only.results.metrics.precision_pct,
            b.timing_only.results.metrics.accuracy_pct
          ],
          backgroundColor: 'rgba(245, 158, 11, 0.65)',
          borderColor: '#d97706',
          borderWidth: 1
        },
        {
          label: 'Combined Statistical Detector',
          data: [
            b.combined.results.metrics.detection_rate_pct,
            b.combined.results.metrics.false_positive_rate_pct,
            b.combined.results.metrics.precision_pct,
            b.combined.results.metrics.accuracy_pct
          ],
          backgroundColor: 'rgba(16, 185, 129, 0.65)',
          borderColor: '#059669',
          borderWidth: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: { title: { display: true, text: 'Percentage (%)' }, beginAtZero: true, max: 100 }
      }
    }
  });
}

// Slider listeners to sync visible text and auto-refresh
function initSliderListeners() {
  // Bayes sliders
  const bayesSliders = ['bayes-prior-slider', 'bayes-sens-slider', 'bayes-fpr-slider', 'binom-n-slider', 'binom-p-slider'];
  bayesSliders.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', () => {
        const valSpan = document.getElementById(`${id}-val`);
        if (valSpan) valSpan.textContent = el.value;
        loadProbabilityModels();
      });
    }
  });

  // CLT sliders
  const cltSliders = ['clt-n-slider', 'clt-reps-slider'];
  cltSliders.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', () => {
        const valSpan = document.getElementById(`${id}-val`);
        if (valSpan) valSpan.textContent = el.value;
      });
    }
  });
  document.getElementById('btn-run-clt')?.addEventListener('click', loadSamplingCLT);
  document.getElementById('clt-feature-select')?.addEventListener('change', loadSamplingCLT);

  // Descriptive feature select
  document.getElementById('desc-feature-select')?.addEventListener('change', updateDescriptiveView);

  // Detector benchmark sliders
  const detSliders = ['det-entropy-slider', 'det-iat-slider', 'det-len-slider'];
  detSliders.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', () => {
        const valSpan = document.getElementById(`${id}-val`);
        if (valSpan) valSpan.textContent = el.value;
        loadDetectorBenchmark();
      });
    }
  });
}

// Global initialization on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initDatasetControls();
  initSliderListeners();
  loadDatasetInfo();
});
