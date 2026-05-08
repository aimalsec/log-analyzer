#!/usr/bin/env python3
"""
Unit tests for Security Log Analyzer
Run with: python -m pytest test_analyzer.py
Or: python test_analyzer.py
"""

import unittest
import tempfile
from pathlib import Path
from datetime import datetime
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from log_analyzer import SecurityLogAnalyzer

class TestLogAnalyzer(unittest.TestCase):
    """Test cases for SecurityLogAnalyzer"""
    
    def setUp(self):
        """Set up test fixtures before each test method"""
        self.analyzer = SecurityLogAnalyzer(threshold=3, time_window=5)
        self.temp_dir = tempfile.mkdtemp()
    
    def create_temp_log(self, content):
        """Helper to create temporary log file"""
        log_file = Path(self.temp_dir) / "test.log"
        with open(log_file, 'w') as f:
            f.write(content)
        return log_file
    
    def test_failed_ssh_detection(self):
        """Test detection of failed SSH attempts"""
        log_content = """Mar 10 02:15:23 server sshd[24567]: Failed password for root from 192.168.1.100 port 34521 ssh2
Mar 10 02:15:25 server sshd[24568]: Failed password for admin from 192.168.1.100 port 34522 ssh2"""
        
        log_file = self.create_temp_log(log_content)
        self.analyzer.process_log_file(log_file)
        
        self.assertEqual(len(self.analyzer.failed_logins), 1)
        self.assertIn('192.168.1.100', self.analyzer.failed_logins)
        self.assertEqual(len(self.analyzer.failed_logins['192.168.1.100']), 2)
    
    def test_invalid_user_detection(self):
        """Test detection of invalid user attempts"""
        log_content = """Mar 10 04:00:10 server sshd[24850]: Invalid user testuser from 198.51.100.77 port 55555"""
        
        log_file = self.create_temp_log(log_content)
        self.analyzer.process_log_file(log_file)
        
        self.assertEqual(len(self.analyzer.user_enumeration), 1)
        self.assertIn('198.51.100.77', self.analyzer.user_enumeration)
    
    def test_brute_force_detection(self):
        """Test brute force detection logic"""
        log_content = """Mar 10 02:15:23 server sshd[24567]: Failed password for root from 45.33.22.11 port 34521 ssh2
Mar 10 02:15:25 server sshd[24568]: Failed password for root from 45.33.22.11 port 34522 ssh2
Mar 10 02:15:27 server sshd[24569]: Failed password for root from 45.33.22.11 port 34523 ssh2"""
        
        log_file = self.create_temp_log(log_content)
        self.analyzer.process_log_file(log_file)
        
        brute_force = self.analyzer.analyze_brute_force()
        self.assertGreater(len(brute_force), 0)
        self.assertEqual(brute_force[0]['ip'], '45.33.22.11')
        self.assertGreaterEqual(brute_force[0]['total_attempts'], 3)
    
    def test_user_enumeration_detection(self):
        """Test user enumeration detection"""
        log_content = """Mar 10 04:00:10 server sshd[24850]: Invalid user user1 from 198.51.100.77 port 55555
Mar 10 04:00:12 server sshd[24851]: Invalid user user2 from 198.51.100.77 port 55556
Mar 10 04:00:14 server sshd[24852]: Invalid user user3 from 198.51.100.77 port 55557
Mar 10 04:00:16 server sshd[24853]: Invalid user user4 from 198.51.100.77 port 55558
Mar 10 04:00:18 server sshd[24854]: Invalid user user5 from 198.51.100.77 port 55559
Mar 10 04:00:20 server sshd[24855]: Invalid user user6 from 198.51.100.77 port 55560"""
        
        log_file = self.create_temp_log(log_content)
        self.analyzer.process_log_file(log_file)
        
        enumeration = self.analyzer.detect_user_enumeration()
        self.assertGreater(len(enumeration), 0)
        self.assertEqual(enumeration[0]['ip'], '198.51.100.77')
        self.assertGreaterEqual(enumeration[0]['unique_usernames_tried'], 5)
    
    def test_no_false_positives_on_good_logs(self):
        """Test that normal logs don't trigger alerts"""
        log_content = """Mar 10 08:00:15 server sshd[30001]: Accepted password for alice from 192.168.1.50 port 52341 ssh2
Mar 10 08:00:18 server sshd[30002]: Accepted password for bob from 192.168.1.51 port 52342 ssh2"""
        
        log_file = self.create_temp_log(log_content)
        self.analyzer.process_log_file(log_file)
        
        self.assertEqual(len(self.analyzer.failed_logins), 0)
        self.assertEqual(len(self.analyzer.user_enumeration), 0)
    
    def test_multiple_ip_tracking(self):
        """Test tracking multiple attacking IPs"""
        log_content = """Mar 10 02:15:23 server sshd[24567]: Failed password for root from 45.33.22.11 port 34521 ssh2
Mar 10 02:15:25 server sshd[24568]: Failed password for root from 103.112.45.67 port 34522 ssh2"""
        
        log_file = self.create_temp_log(log_content)
        self.analyzer.process_log_file(log_file)
        
        self.assertEqual(len(self.analyzer.failed_logins), 2)
        self.assertIn('45.33.22.11', self.analyzer.failed_logins)
        self.assertIn('103.112.45.67', self.analyzer.failed_logins)
    
    def test_time_window_enforcement(self):
        """Test that time window threshold works"""
        # Create logs with timestamps outside the time window
        log_content = """Jan 15 08:23:15 server sshd[24567]: Failed password for root from 45.33.22.11 port 34521 ssh2
Jan 15 08:23:17 server sshd[24568]: Failed password for root from 45.33.22.11 port 34522 ssh2
Jan 15 08:30:20 server sshd[24569]: Failed password for root from 45.33.22.11 port 34523 ssh2"""
        
        log_file = self.create_temp_log(log_content)
        self.analyzer.process_log_file(log_file)
        
        brute_force = self.analyzer.analyze_brute_force()
        # Should not detect because attempts spread over time
        self.assertEqual(len(brute_force), 0)
    
    def test_json_output(self):
        """Test JSON report generation"""
        log_content = """Mar 10 02:15:23 server sshd[24567]: Failed password for root from 45.33.22.11 port 34521 ssh2"""
        
        log_file = self.create_temp_log(log_content)
        self.analyzer.process_log_file(log_file)
        
        report = self.analyzer.generate_report(output_format='json')
        self.assertIsInstance(report, str)
        self.assertIn('"summary"', report)
        self.assertIn('"brute_force_attacks"', report)
    
    def test_csv_output(self):
        """Test CSV report generation"""
        log_content = """Mar 10 02:15:23 server sshd[24567]: Failed password for root from 45.33.22.11 port 34521 ssh2"""
        
        log_file = self.create_temp_log(log_content)
        self.analyzer.process_log_file(log_file)
        
        report = self.analyzer.generate_report(output_format='csv')
        self.assertIsInstance(report, str)
        self.assertIn('Type,IP,Total_Attempts', report)
    
    def test_top_offenders(self):
        """Test top offenders ranking"""
        log_content = """Mar 10 02:15:23 server sshd[24567]: Failed password for root from 45.33.22.11 port 34521 ssh2
Mar 10 02:15:25 server sshd[24568]: Failed password for root from 103.112.45.67 port 34522 ssh2
Mar 10 02:15:27 server sshd[24569]: Failed password for root from 45.33.22.11 port 34523 ssh2"""
        
        log_file = self.create_temp_log(log_content)
        self.analyzer.process_log_file(log_file)
        
        top_ips = self.analyzer.get_top_offenders(limit=1)
        self.assertEqual(len(top_ips), 1)
        self.assertEqual(top_ips[0][0], '45.33.22.11')
        self.assertEqual(top_ips[0][1], 2)


def run_tests():
    """Run all tests with verbose output"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestLogAnalyzer)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == "__main__":
    print("=" * 60)
    print("RUNNING SECURITY LOG ANALYZER TESTS")
    print("=" * 60)
    success = run_tests()
    print("\n" + "=" * 60)
    if success:
        print("✅ ALL TESTS PASSED!")
    else:
        print("❌ SOME TESTS FAILED - Check the output above")
    print("=" * 60)
    sys.exit(0 if success else 1)