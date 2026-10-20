/**
 * Main Frontend Application Script
 * Probability and Statistics DNS Project
 * Simplified, Student-Friendly 5-Section Architecture
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
let descriptiveCache = null;

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

      onTabActivated(targetId);
    });
  });
}

function onTabActivated(tabId) {
  if (tabId === 'tab-analysis') {
    loadDescriptiveStats();
  } else if (tabId === 'tab-probability') {
    loadProbabilityModels();
  } else if (tabId === 'tab-hypothesis') {
    loadHypothesisTests();
  } else if (tabId === 'tab-correlation') {
    loadCorrelationAndResults();
  }
}

// =============================================================
// 1. OVERVIEW & DATASET
// =============================================================

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

    const badge = document.getElementById('metric-dataset-badge');
    if (badge) {
      badge.textContent = data.is_simulated ? "Simulated sample data" : "Custom uploaded data";
    }

    // Populate dataset selector with friendly names
    const selector = document.getElementById('dataset-select');
    selector.innerHTML = '';
    data.available_datasets.forEach(name => {
      const opt = document.createElement('option');
      opt.value = name;
      let label = name;
      if (name === 'sample_dns_traffic.csv') {
        label = 'Simulated Sample: Mixed Baseline (1,200 rows)';
      } else if (name === 'sample_high_entropy_tunneling.csv') {
        label = 'Simulated Sample: Attack Surge (700 rows)';
      } else if (name === 'sample_normal_workday.csv') {
        label = 'Simulated Sample: Routine Browsing (920 rows)';
      } else {
        label = `Custom CSV: ${name}`;
      }
      opt.textContent = label;
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

    if (!data.records || data.records.length === 0) {
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
      descriptiveCache = null;
      await loadDatasetInfo();
      const activeBtn = document.querySelector('.nav-tab-btn.active');
      if (activeBtn) onTabActivated(activeBtn.getAttribute('data-tab'));
    }
  });

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

  // CSV Upload handler with friendly validation feedback
  const uploadForm = document.getElementById('upload-form');
  const uploadFile = document.getElementById('upload-file');
  const uploadStatus = document.getElementById('upload-status');

  uploadForm?.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!uploadFile.files || uploadFile.files.length === 0) {
      uploadStatus.textContent = 'Please choose a CSV file first.';
      uploadStatus.style.color = 'var(--suspicious-color)';
      return;
    }

    const formData = new FormData();
    formData.append('file', uploadFile.files[0]);

    uploadStatus.textContent = 'Uploading and processing features...';
    uploadStatus.style.color = 'var(--text-muted)';

    try {
      const res = await fetch('/api/dataset/upload', {
        method: 'POST',
        body: formData
      });
      const data = await res.json();
      if (data.status === 'success') {
        uploadStatus.textContent = `Success: Analyzed ${data.rows} records.`;
        uploadStatus.style.color = 'var(--normal-color)';
        currentPage = 1;
        descriptiveCache = null;
        await loadDatasetInfo();
        const activeBtn = document.querySelector('.nav-tab-btn.active');
        if (activeBtn) onTabActivated(activeBtn.getAttribute('data-tab'));
      } else {
        uploadStatus.textContent = `Upload Error: ${data.message}`;
        uploadStatus.style.color = 'var(--suspicious-color)';
      }
    } catch (err) {
      uploadStatus.textContent = 'Upload failed. Please ensure file is valid CSV.';
      uploadStatus.style.color = 'var(--suspicious-color)';
    }
  });
}

// =============================================================
// 2. DATA ANALYSIS (DESCRIPTIVE STATISTICS)
// =============================================================

async function loadDescriptiveStats() {
  try {
    if (!descriptiveCache) {
      const res = await fetch('/api/stats/descriptive');
      const data = await res.json();
      if (data.status !== 'success') return;
      descriptiveCache = data.features;
    }
    updateDescriptiveView();
  } catch (err) {
    console.error("Failed to load descriptive stats:", err);
  }
}

function updateDescriptiveView() {
  if (!descriptiveCache) return;
  const feat = document.getElementById('desc-feature-select').value;
  const featData = descriptiveCache[feat];
  if (!featData) return;

  const normal = featData.descriptive.normal;
  const suspicious = featData.descriptive.suspicious;
  const overall = featData.descriptive.overall;

  const rows = [
    { label: "Sample Size (n)", n: normal.n, s: suspicious.n, o: overall.n, format: v => v },
    { label: "Mean (μ / x̄)", n: normal.mean, s: suspicious.mean, o: overall.mean, format: v => v.toFixed(4) },
    { label: "Median (Q2)", n: normal.median, s: suspicious.median, o: overall.median, format: v => v.toFixed(4) },
    { label: "Sample Variance (s²)", n: normal.sample_variance, s: suspicious.sample_variance, o: overall.sample_variance, format: v => v.toFixed(4) },
    { label: "Sample Std Dev (s)", n: normal.sample_std, s: suspicious.sample_std, o: overall.sample_std, format: v => v.toFixed(4) },
    { label: "Coeff. of Variation (CV %)", n: normal.coefficient_of_variation_pct, s: suspicious.coefficient_of_variation_pct, o: overall.coefficient_of_variation_pct, format: v => v.toFixed(2) + '%' },
    { label: "1st Quartile (Q1)", n: normal.q1, s: suspicious.q1, o: overall.q1, format: v => v.toFixed(4) },
    { label: "3rd Quartile (Q3)", n: normal.q3, s: suspicious.q3, o: overall.q3, format: v => v.toFixed(4) },
    { label: "Interquartile Range (IQR)", n: normal.iqr, s: suspicious.iqr, o: overall.iqr, format: v => v.toFixed(4) },
    { label: "Minimum & Maximum", n: `${normal.min} to ${normal.max}`, s: `${suspicious.min} to ${suspicious.max}`, o: `${overall.min} to ${overall.max}`, format: v => v }
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

  renderHistogramChart(feat, featData.histograms);

  // Viva Explanation
  const diffPct = (((suspicious.mean - normal.mean) / normal.mean) * 100).toFixed(1);
  const featName = feat === 'entropy' ? 'Shannon Entropy' : feat === 'query_length' ? 'Query Length' : 'Inter-Arrival Time';
  const unit = feat === 'entropy' ? 'bits/char' : feat === 'query_length' ? 'characters' : 'seconds';

  document.getElementById('desc-interpretation-text').innerHTML = `
    <strong>Viva Explanation for ${featName}:</strong><br>
    • <strong>Central Tendency:</strong> Normal queries average <code>${normal.mean} ${unit}</code>, while suspicious queries average <code>${suspicious.mean} ${unit}</code> (a <strong>${Math.abs(diffPct)}% ${diffPct >= 0 ? 'increase' : 'decrease'}</strong>).<br>
    • <strong>Variability (CV):</strong> Normal CV is <code>${normal.coefficient_of_variation_pct}%</code> vs suspicious CV <code>${suspicious.coefficient_of_variation_pct}%</code>. A lower CV indicates tighter clustering around the mean, while a higher CV indicates greater relative dispersion.<br>
    • <strong>Distribution Separation:</strong> The histogram confirms that the two groups occupy distinct regions of the frequency distribution, making ${featName} a valuable statistical differentiator.
  `;
}

function renderHistogramChart(feature, histograms) {
  destroyChart('descHistogram');
  const ctx = document.getElementById('descHistogramChart').getContext('2d');

  const normHist = histograms.normal;
  const suspHist = histograms.suspicious;
  const labels = normHist.labels.length >= suspHist.labels.length ? normHist.labels : suspHist.labels;

  charts['descHistogram'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [
        {
          label: 'Normal Traffic Frequency',
          data: normHist.counts,
          backgroundColor: 'rgba(5, 150, 105, 0.65)',
          borderColor: '#059669',
          borderWidth: 1
        },
        {
          label: 'Suspicious Traffic Frequency',
          data: suspHist.counts,
          backgroundColor: 'rgba(220, 38, 38, 0.65)',
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
        x: { title: { display: true, text: `${feature.replace('_', ' ').toUpperCase()} Bins` } },
        y: { title: { display: true, text: 'Query Count (Frequency)' }, beginAtZero: true }
      }
    }
  });
}

// =============================================================
// 3. PROBABILITY & DISTRIBUTIONS
// =============================================================

async function loadProbabilityModels() {
  const prior = parseFloat(document.getElementById('bayes-prior-slider').value);
  const sens = parseFloat(document.getElementById('bayes-sens-slider').value);
  const fpr = parseFloat(document.getElementById('bayes-fpr-slider').value);
  const nBatch = parseInt(document.getElementById('binom-n-slider').value);

  try {
    const res = await fetch('/api/stats/probability', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        prior_tunnel: prior,
        sensitivity: sens,
        fpr: fpr,
        n_batch: nBatch
      })
    });
    const data = await res.json();
    if (data.status !== 'success') return;

    // Empirical Base Rates
    const ep = data.empirical_probs;
    document.getElementById('prob-p-normal').textContent = `${ep.p_normal} (${(ep.p_normal * 100).toFixed(1)}%, n=${ep.normal_count})`;
    document.getElementById('prob-p-suspicious').textContent = `${ep.p_suspicious} (${(ep.p_suspicious * 100).toFixed(1)}%, n=${ep.suspicious_count})`;

    // Bayes' Theorem
    const bayes = data.bayes_theorem;
    document.getElementById('bayes-posterior-val').textContent = `${bayes.posterior_pct}%`;
    document.getElementById('bayes-npv-val').textContent = `${(bayes.posterior_normal_given_no_alarm * 100).toFixed(1)}%`;
    document.getElementById('bayes-note-text').innerHTML = `
      <strong>The Base Rate Fallacy:</strong> Even with high sensitivity (${(bayes.sensitivity * 100).toFixed(0)}%), if the true prior rate of suspicious queries is small (${(bayes.prior_tunnel * 100).toFixed(1)}%), the probability of a true positive given an alarm is <strong>${bayes.posterior_pct}%</strong> because the overwhelming volume of normal queries generates false alarms.
    `;

    // Binomial Distribution
    const binom = data.binomial_batch;
    document.getElementById('binom-mean-val').textContent = `Expected Value E[X] = np = ${binom.mean}`;
    document.getElementById('binom-var-val').textContent = `Variance Var(X) = ${binom.variance} (σ = ${binom.std_dev})`;
    renderBinomialChart(binom);

    // Normal Fit & Confidence Interval
    const nf = data.normal_fit;
    if (nf && nf.ci_95) {
      document.getElementById('norm-ci95-val').textContent = `[ ${nf.ci_95.lower_bound} , ${nf.ci_95.upper_bound} ] bits`;
      document.getElementById('norm-ci-interpretation').innerHTML = `
        <strong>Viva Interpretation:</strong> We are 95% confident that the true population mean entropy of DNS queries lies between <strong>${nf.ci_95.lower_bound}</strong> and <strong>${nf.ci_95.upper_bound}</strong> bits per character (Margin of Error: ±${nf.ci_95.margin_of_error}).
      `;
    }
    if (nf && nf.empirical_rule) {
      document.getElementById('norm-rule-1sd').textContent = `${nf.empirical_rule.within_1_sigma_pct}%`;
      document.getElementById('norm-rule-2sd').textContent = `${nf.empirical_rule.within_2_sigma_pct}%`;
      document.getElementById('norm-rule-3sd').textContent = `${nf.empirical_rule.within_3_sigma_pct}%`;
    }
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
          label: 'P(X = k) [PMF]',
          data: binom.pmf,
          backgroundColor: 'rgba(37, 99, 235, 0.65)',
          borderColor: '#2563eb',
          borderWidth: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { title: { display: true, text: `Number of Suspicious Queries (k) in batch n=${binom.n}` } },
        y: { title: { display: true, text: 'Probability P(X = k)' }, beginAtZero: true }
      }
    }
  });
}

// =============================================================
// 4. HYPOTHESIS TESTING
// =============================================================

async function loadHypothesisTests() {
  try {
    const res = await fetch('/api/stats/hypothesis');
    const data = await res.json();
    if (data.status !== 'success') return;

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
        <td class="numeric">${t.p_value < 0.0001 ? '< 0.0001' : t.p_value.toFixed(4)}</td>
        <td class="numeric">${t.cohens_d}</td>
        <td><span class="badge ${badgeClass}">${verdict}</span></td>
      `;
      tBody.appendChild(tr);
    });
  } catch (err) {
    console.error("Failed to load hypothesis tests:", err);
  }
}

// =============================================================
// 5. CORRELATION & RESULTS
// =============================================================

async function loadCorrelationAndResults() {
  const entropyThresh = parseFloat(document.getElementById('det-entropy-slider').value);
  const iatThresh = parseFloat(document.getElementById('det-iat-slider').value);

  try {
    // 1. Fetch Correlation & Regression
    const resReg = await fetch('/api/stats/regression');
    const dataReg = await resReg.json();
    if (dataReg.status === 'success') {
      const reg = dataReg.regression;
      if (reg.pairwise_correlations) {
        document.getElementById('corr-len-ent').textContent = `r = ${reg.pairwise_correlations.length_entropy}`;
        document.getElementById('corr-len-iat').textContent = `r = ${reg.pairwise_correlations.length_iat}`;
        document.getElementById('corr-ent-iat').textContent = `r = ${reg.pairwise_correlations.entropy_iat}`;
      }
      document.getElementById('reg-r2').textContent = `${(reg.r_squared * 100).toFixed(1)}% (R² = ${reg.r_squared})`;
      document.getElementById('reg-equation').textContent = `Entropy = ${reg.intercept} + (${reg.slope} × Length)`;
      document.getElementById('reg-interpretation-text').innerHTML = `
        <strong>Viva Interpretation:</strong><br>
        • <strong>Pearson r = ${reg.pearson_r}:</strong> Indicates a ${reg.pearson_r > 0.6 ? 'strong positive' : 'moderate'} linear correlation. As query length increases, Shannon entropy also increases because encoded payloads introduce diverse character sets.<br>
        • <strong>R² = ${(reg.r_squared * 100).toFixed(1)}%:</strong> ${(reg.r_squared * 100).toFixed(1)}% of the total variation in Shannon entropy can be explained by query length.
      `;

      renderRegressionChart(reg);
    }

    // 2. Fetch Supporting Detection Benchmark
    const resDet = await fetch('/api/detector/evaluate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        entropy_threshold: entropyThresh,
        iat_threshold: iatThresh,
        length_threshold: 40
      })
    });
    const dataDet = await resDet.json();
    if (dataDet.status === 'success') {
      const b = dataDet.benchmark.detectors;

      // Update Confusion Matrix for Combined
      const cm = b.combined.results.confusion_matrix;
      document.getElementById('cm-combined-tp').textContent = cm.tp;
      document.getElementById('cm-combined-fp').textContent = cm.fp;
      document.getElementById('cm-combined-fn').textContent = cm.fn;
      document.getElementById('cm-combined-tn').textContent = cm.tn;

      // Update Table
      const tbody = document.getElementById('det-metrics-tbody');
      tbody.innerHTML = '';
      const list = [
        { name: "Entropy-Only", obj: b.entropy_only },
        { name: "Timing-Only", obj: b.timing_only },
        { name: "Combined Detector", obj: b.combined }
      ];
      list.forEach(item => {
        const m = item.obj.results.metrics;
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td><strong>${item.name}</strong></td>
          <td class="numeric">${m.detection_rate_pct}%</td>
          <td class="numeric" style="color: ${m.false_positive_rate_pct > 5 ? 'var(--suspicious-color)' : 'var(--text-main)'};">${m.false_positive_rate_pct}%</td>
          <td class="numeric">${m.precision_pct}%</td>
          <td class="numeric"><strong>${m.accuracy_pct}%</strong></td>
        `;
        tbody.appendChild(tr);
      });
    }
  } catch (err) {
    console.error("Failed to load correlation and results:", err);
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
          backgroundColor: 'rgba(37, 99, 235, 0.45)',
          borderColor: '#2563eb',
          pointRadius: 3
        },
        {
          type: 'line',
          label: `Fitted OLS Line (y = ${reg.intercept} + ${reg.slope}x)`,
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
        x: { title: { display: true, text: 'Query Length (characters)' } },
        y: { title: { display: true, text: 'Shannon Entropy (bits/char)' }, min: 1.0, max: 6.0 }
      }
    }
  });
}

// Slider listeners to sync visible text and auto-refresh
function initSliderListeners() {
  // Bayes sliders
  const bayesSliders = ['bayes-prior-slider', 'bayes-sens-slider', 'bayes-fpr-slider', 'binom-n-slider'];
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

  // Descriptive feature select
  document.getElementById('desc-feature-select')?.addEventListener('change', updateDescriptiveView);

  // Detector benchmark sliders
  const detSliders = ['det-entropy-slider', 'det-iat-slider'];
  detSliders.forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener('input', () => {
        const valSpan = document.getElementById(`${id}-val`);
        if (valSpan) valSpan.textContent = el.value;
        loadCorrelationAndResults();
      });
    }
  });
}

// Global initialization
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initDatasetControls();
  initSliderListeners();
  loadDatasetInfo();
});
