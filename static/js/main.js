/**
 * Main Frontend Application Script
 * Probability and Statistics DNS Project
 * Clean, Simple, Slider-Free Architecture
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
  } else if (tabId === 'tab-results' || tabId === 'tab-correlation') {
    loadResultsAndConclusion();
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
    const elEnt = document.getElementById('metric-mean-entropy');
    if (elEnt) elEnt.textContent = `${data.mean_entropy} bits`;
    document.getElementById('metric-mean-length').textContent = `${data.mean_length} chars`;
    document.getElementById('metric-mean-iat').textContent = `${data.mean_iat_seconds} s`;

    const badge = document.getElementById('metric-dataset-badge');
    if (badge) {
      badge.textContent = data.is_simulated ? "Simulated sample data" : "Custom dataset";
    }

    // Populate dataset selector with friendly names
    const selector = document.getElementById('dataset-select');
    selector.innerHTML = '';
    data.available_datasets.forEach(name => {
      const opt = document.createElement('option');
      opt.value = name;
      let label = name;
      if (name === 'sample_dns_traffic.csv') {
        label = 'Mixed Baseline (1,200 rows)';
      } else if (name === 'sample_high_entropy_tunneling.csv') {
        label = 'Attack Surge (700 rows)';
      } else if (name === 'sample_normal_workday.csv') {
        label = 'Routine Browsing (920 rows)';
      } else {
        label = name;
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
    { label: "Mean", n: normal.mean, s: suspicious.mean, o: overall.mean, format: v => v.toFixed(4) },
    { label: "Median", n: normal.median, s: suspicious.median, o: overall.median, format: v => v.toFixed(4) },
    { label: "Sample Variance", n: normal.sample_variance, s: suspicious.sample_variance, o: overall.sample_variance, format: v => v.toFixed(4) },
    { label: "Sample Standard Deviation", n: normal.sample_std, s: suspicious.sample_std, o: overall.sample_std, format: v => v.toFixed(4) },
    { label: "Coefficient of Variation (%)", n: normal.coefficient_of_variation_pct, s: suspicious.coefficient_of_variation_pct, o: overall.coefficient_of_variation_pct, format: v => v.toFixed(2) + '%' },
    { label: "First Quartile (Q1)", n: normal.q1, s: suspicious.q1, o: overall.q1, format: v => v.toFixed(4) },
    { label: "Third Quartile (Q3)", n: normal.q3, s: suspicious.q3, o: overall.q3, format: v => v.toFixed(4) },
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

  // Clean explanation text
  const diffPct = (((suspicious.mean - normal.mean) / normal.mean) * 100).toFixed(1);
  const featName = feat === 'query_length' ? 'Query Length' : feat === 'inter_arrival_time' ? 'Inter-Arrival Time' : 'Feature';
  const unit = feat === 'query_length' ? 'characters' : feat === 'inter_arrival_time' ? 'seconds' : '';

  document.getElementById('desc-interpretation-text').innerHTML = `
    <strong>Statistical Takeaway:</strong><br>
    • <strong>Central Tendency:</strong> Normal queries average <code>${normal.mean} ${unit}</code>, while suspicious queries average <code>${suspicious.mean} ${unit}</code> (${Math.abs(diffPct)}% ${diffPct >= 0 ? 'increase' : 'decrease'}).<br>
    • <strong>Relative Variability:</strong> Normal CV is <code>${normal.coefficient_of_variation_pct}%</code> versus suspicious CV <code>${suspicious.coefficient_of_variation_pct}%</code>. A lower CV indicates tighter clustering around the mean.<br>
    • <strong>Distribution Separation:</strong> The histogram shows that normal and suspicious queries form distinct frequency distributions, confirming that ${featName} provides clear separation.
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
          backgroundColor: 'rgba(87, 83, 78, 0.75)',
          borderColor: '#44403c',
          borderWidth: 1
        },
        {
          label: 'Suspicious Traffic Frequency',
          data: suspHist.counts,
          backgroundColor: 'rgba(185, 28, 28, 0.75)',
          borderColor: '#991b1b',
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
  try {
    const res = await fetch('/api/stats/probability', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        n_batch: 30
      })
    });
    const data = await res.json();
    if (data.status !== 'success') return;

    // Empirical Base Rates (plain text, no $ signs)
    const ep = data.empirical_probs;
    document.getElementById('prob-p-normal').textContent = `${(ep.p_normal * 100).toFixed(1)}% (${ep.normal_count.toLocaleString()} queries)`;
    document.getElementById('prob-p-suspicious').textContent = `${(ep.p_suspicious * 100).toFixed(1)}% (${ep.suspicious_count.toLocaleString()} queries)`;

    // Bayes' Theorem
    const bayes = data.bayes_theorem;
    document.getElementById('bayes-posterior-val').textContent = `${bayes.posterior_pct}%`;
    document.getElementById('bayes-npv-val').textContent = `${(bayes.posterior_normal_given_no_alarm * 100).toFixed(1)}%`;
    document.getElementById('bayes-note-text').innerHTML = `
      Even with high sensitivity (94%), if the true proportion of suspicious traffic is low (${(bayes.prior_tunnel * 100).toFixed(1)}%), the probability of a true positive given an alarm is <strong>${bayes.posterior_pct}%</strong>. This illustrates the Base Rate Fallacy: false alarms can occur when normal traffic overwhelmingly outnumbers attacks.
    `;

    // Binomial Distribution
    const binom = data.binomial_batch;
    document.getElementById('binom-mean-val').textContent = `Expected Value: ${binom.mean}`;
    document.getElementById('binom-var-val').textContent = `Variance: ${binom.variance} (Std Dev = ${binom.std_dev})`;
    renderBinomialChart(binom);

    // Normal Fit & Confidence Interval
    const nf = data.normal_fit;
    if (nf && nf.ci_95) {
      document.getElementById('norm-ci95-val').textContent = `[ ${nf.ci_95.lower_bound} , ${nf.ci_95.upper_bound} ] chars`;
      document.getElementById('norm-ci-interpretation').innerHTML = `
        We are 95% confident that the true population mean domain query length lies between <strong>${nf.ci_95.lower_bound}</strong> and <strong>${nf.ci_95.upper_bound}</strong> characters (Margin of Error: ±${nf.ci_95.margin_of_error}).
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
      labels: binom.k_values.slice(0, 16),
      datasets: [
        {
          label: 'Probability P(X = k)',
          data: binom.pmf.slice(0, 16),
          backgroundColor: 'rgba(24, 24, 27, 0.75)',
          borderColor: '#18181b',
          borderWidth: 1
        }
      ]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { title: { display: true, text: `Number of Suspicious Queries (k) in batch n=30` } },
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

    ['query_length', 'inter_arrival_time'].forEach(feat => {
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

// Global initialization
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initDatasetControls();
  // Descriptive feature select listener
  document.getElementById('desc-feature-select')?.addEventListener('change', updateDescriptiveView);
  loadDatasetInfo();
});
