"""
Unit and Integration Tests for Probability and Statistics DNS Project.
"""

import unittest
import numpy as np
import pandas as pd
import dns_utils
import stats_engine
import detector


class TestDNSUtils(unittest.TestCase):
    def test_shannon_entropy_constant(self):
        # Repetitive single char should have entropy 0
        self.assertEqual(dns_utils.shannon_entropy("aaaaaa"), 0.0)

    def test_shannon_entropy_empty(self):
        self.assertEqual(dns_utils.shannon_entropy(""), 0.0)

    def test_shannon_entropy_comparison(self):
        # Normal english domain vs random base64 string
        normal_domain = "google.com"
        tunnel_domain = "a8b9c0d1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s6t7u8v9"
        ent_normal = dns_utils.shannon_entropy(normal_domain)
        ent_tunnel = dns_utils.shannon_entropy(tunnel_domain)
        self.assertGreater(ent_tunnel, ent_normal)
        self.assertGreater(ent_tunnel, 4.0)

    def test_dataframe_processing(self):
        raw_data = pd.DataFrame({
            "query": ["google.com", "dnscat.a89fbc012.tunnel.net"],
            "timestamp": ["2026-10-18 10:00:00", "2026-10-18 10:00:01"],
            "label": ["Normal", "Suspicious"]
        })
        processed = dns_utils.process_dns_dataframe(raw_data)
        self.assertIn("entropy", processed.columns)
        self.assertIn("query_length", processed.columns)
        self.assertIn("inter_arrival_time", processed.columns)
        self.assertEqual(len(processed), 2)


class TestStatsEngine(unittest.TestCase):
    def setUp(self):
        np.random.seed(42)
        self.normal_vals = pd.Series(np.random.normal(loc=3.0, scale=0.3, size=100))
        self.tunnel_vals = pd.Series(np.random.normal(loc=4.6, scale=0.2, size=100))

    def test_descriptive_stats(self):
        stats = stats_engine.compute_descriptive_stats(self.normal_vals)
        self.assertAlmostEqual(stats['mean'], 3.0, delta=0.1)
        self.assertGreater(stats['sample_variance'], 0.0)
        self.assertGreater(stats['sample_std'], 0.0)
        self.assertIn('coefficient_of_variation_pct', stats)
        self.assertIn('iqr', stats)

    def test_bayes_theorem(self):
        # Prior = 1%, Sensitivity = 95%, FPR = 5%
        res = stats_engine.bayes_theorem_analysis(prior_tunnel=0.01, sensitivity=0.95, fpr=0.05)
        # P(T|A) = (0.95 * 0.01) / (0.95 * 0.01 + 0.05 * 0.99) = 0.0095 / (0.0095 + 0.0495) = 0.0095 / 0.059 = ~0.161
        self.assertAlmostEqual(res['posterior_tunnel_given_alarm'], 0.161, delta=0.01)
        self.assertIn("base_rate_fallacy_note", res)

    def test_binomial_model(self):
        binom = stats_engine.binomial_model(n=20, p=0.25)
        self.assertEqual(binom['mean'], 5.0)
        self.assertAlmostEqual(sum(binom['pmf']), 1.0, delta=0.001)

    def test_clt_simulation(self):
        clt = stats_engine.central_limit_theorem_simulation(self.normal_vals, sample_size_n=25, num_samples_N=300)
        self.assertAlmostEqual(clt['empirical_mean_of_means'], clt['population_mean'], delta=0.05)
        self.assertAlmostEqual(clt['empirical_standard_error'], clt['theoretical_standard_error'], delta=0.02)

    def test_confidence_intervals(self):
        ci = stats_engine.compute_confidence_intervals(self.normal_vals)
        ci_95 = ci['confidence_intervals']['95%']
        self.assertLess(ci_95['lower_bound'], ci['sample_mean'])
        self.assertGreater(ci_95['upper_bound'], ci['sample_mean'])

    def test_welch_t_test(self):
        t_res = stats_engine.two_sample_welch_t_test(
            self.normal_vals, self.tunnel_vals, "Normal", "Suspicious", "Entropy"
        )
        self.assertTrue(t_res['reject_h0_alpha_05'])
        self.assertLess(t_res['p_value'], 0.001)
        self.assertIn('type_errors', t_res)

    def test_correlation_and_regression(self):
        df = pd.DataFrame({
            "query_length": [15, 20, 25, 60, 80, 100],
            "entropy": [2.5, 2.8, 3.1, 4.2, 4.5, 4.8]
        })
        reg = stats_engine.correlation_and_regression(df, 'query_length', 'entropy')
        self.assertGreater(reg['pearson_r'], 0.9)
        self.assertGreater(reg['r_squared'], 0.8)
        self.assertGreater(reg['slope'], 0.0)


class TestDetector(unittest.TestCase):
    def test_detector_evaluation(self):
        df = pd.DataFrame({
            "entropy": [2.5, 3.0, 3.2, 4.5, 4.8, 4.9],
            "inter_arrival_time": [2.1, 1.5, 3.0, 0.05, 0.1, 0.02],
            "query_length": [14, 18, 20, 80, 95, 110],
            "label": ["Normal", "Normal", "Normal", "Suspicious", "Suspicious", "Suspicious"]
        })
        res = detector.run_detection_benchmark(df, entropy_threshold=4.0, iat_threshold=0.2, length_threshold=50)
        self.assertIn("entropy_only", res['detectors'])
        self.assertIn("timing_only", res['detectors'])
        self.assertIn("combined", res['detectors'])
        self.assertEqual(res['detectors']['entropy_only']['results']['metrics']['detection_rate_pct'], 100.0)
        self.assertEqual(res['detectors']['entropy_only']['results']['metrics']['false_positive_rate_pct'], 0.0)


if __name__ == '__main__':
    unittest.main()
