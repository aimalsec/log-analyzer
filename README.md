# 🔐 Security Log Analyzer

A Python-based log analysis tool for detecting cybersecurity threats including brute force attacks, user enumeration, and suspicious authentication patterns.

## 🚀 Quick Start

```bash
# Test with sample attack logs
python src/log_analyzer.py -l logs/attack_simulation.log

# Test with normal logs (should have few/no alerts)
python src/log_analyzer.py -l logs/sample_secure.log

# Run unit tests
python tests/test_analyzer.py