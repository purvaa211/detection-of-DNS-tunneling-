"""
Integration tests for Flask application endpoints and API responses.
"""

import unittest
import json
import io
import os
from app import app


class TestAppEndpoints(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_index_route(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Detecting DNS Tunneling Using Entropy & Timing Statistics", response.data)

    def test_dataset_info_endpoint(self):
        response = self.app.get('/api/dataset/info')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        self.assertGreater(data['total_queries'], 0)
        self.assertIn('mean_entropy', data)
        self.assertIn('available_datasets', data)
        self.assertIn('is_simulated', data)

    def test_dataset_records_endpoint(self):
        response = self.app.get('/api/dataset/records?page=1&page_size=10')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(len(data['records']), 10)
        self.assertIn('query', data['records'][0])
        self.assertIn('entropy', data['records'][0])

    def test_descriptive_stats_endpoint(self):
        response = self.app.get('/api/stats/descriptive')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('entropy', data['features'])
        self.assertIn('query_length', data['features'])
        self.assertIn('inter_arrival_time', data['features'])
        self.assertIn('mean', data['features']['entropy']['descriptive']['normal'])

    def test_probability_endpoint(self):
        payload = {
            "prior_tunnel": 0.05,
            "sensitivity": 0.95,
            "fpr": 0.04,
            "n_batch": 30,
            "p_batch": 0.15
        }
        response = self.app.post('/api/stats/probability', json=payload)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('bayes_theorem', data)
        self.assertIn('binomial_batch', data)
        self.assertIn('empirical_probs', data)
        self.assertIn('normal_fit', data)

    def test_sampling_clt_endpoint(self):
        payload = {
            "feature": "entropy",
            "sample_size_n": 30,
            "num_samples_N": 300
        }
        response = self.app.post('/api/stats/sampling', json=payload)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('clt_simulation', data)
        self.assertIn('confidence_intervals', data)
        self.assertIn('zscore_and_normality', data)

    def test_hypothesis_endpoint(self):
        response = self.app.get('/api/stats/hypothesis')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('two_sample_t_tests', data)
        self.assertIn('chi_square_test', data)
        self.assertIn('one_way_anova', data)

    def test_regression_endpoint(self):
        response = self.app.get('/api/stats/regression')
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('regression', data)
        self.assertIn('pearson_r', data['regression'])
        self.assertIn('slope', data['regression'])
        self.assertIn('pairwise_correlations', data['regression'])

    def test_detector_evaluate_endpoint(self):
        payload = {
            "entropy_threshold": 3.75,
            "iat_threshold": 0.30,
            "length_threshold": 40
        }
        response = self.app.post('/api/detector/evaluate', json=payload)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        self.assertIn('benchmark', data)
        self.assertIn('entropy_only', data['benchmark']['detectors'])
        self.assertIn('combined', data['benchmark']['detectors'])

    def test_switch_dataset_endpoint(self):
        payload = {"filename": "sample_high_entropy_tunneling.csv"}
        response = self.app.post('/api/dataset/switch', json=payload)
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['dataset_name'], "sample_high_entropy_tunneling.csv")

        # Switch back to default
        self.app.post('/api/dataset/switch', json={"filename": "sample_dns_traffic.csv"})

    def test_upload_dataset_endpoint(self):
        csv_content = "timestamp,query,label\n2026-10-18 10:00:00,google.com,Normal\n2026-10-18 10:00:01,test123456789.tunnel.net,Suspicious\n"
        data = {
            'file': (io.BytesIO(csv_content.encode('utf-8')), 'test_upload.csv')
        }
        response = self.app.post('/api/dataset/upload', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 200)
        res_data = json.loads(response.data)
        self.assertEqual(res_data['status'], 'success')

        # Clean up test upload
        test_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test_upload.csv')
        if os.path.exists(test_path):
            os.remove(test_path)
        # Restore default
        self.app.post('/api/dataset/switch', json={"filename": "sample_dns_traffic.csv"})

    def test_upload_empty_csv_validation(self):
        data = {
            'file': (io.BytesIO(b""), 'empty.csv')
        }
        response = self.app.post('/api/dataset/upload', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)
        res_data = json.loads(response.data)
        self.assertEqual(res_data['status'], 'error')

    def test_upload_missing_query_column_validation(self):
        bad_csv = "col1,col2\nval1,val2\nval3,val4\n"
        data = {
            'file': (io.BytesIO(bad_csv.encode('utf-8')), 'bad.csv')
        }
        response = self.app.post('/api/dataset/upload', data=data, content_type='multipart/form-data')
        self.assertEqual(response.status_code, 400)
        res_data = json.loads(response.data)
        self.assertEqual(res_data['status'], 'error')


if __name__ == '__main__':
    unittest.main()
