#!/usr/bin/env python3
"""
Cybersecurity Log Analyzer
Author: Aimal Khan
Description: Analyzes system logs for security threats including brute force attempts,
             suspicious IPs, and user enumeration.
"""

import re
import json
import csv
from collections import defaultdict, Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Set, Tuple
import argparse

class SecurityLogAnalyzer:
    """Main log analyzer class for detecting security threats"""
    
    def __init__(self, threshold: int = 10, time_window: int = 60):
        """
        Initialize the analyzer with configurable thresholds
        
        Args:
            threshold: Number of failed attempts to flag as brute force
            time_window: Time window in minutes for brute force detection
        """
        self.threshold = threshold
        self.time_window = time_window
        self.failed_logins = defaultdict(list)
        self.suspicious_ips = set()
        self.user_enumeration = defaultdict(list)
        
        # Regex patterns for different log formats
        self.patterns = {
            'failed_ssh': re.compile(r'Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)'),
            'invalid_user': re.compile(r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'),
            'auth_failure': re.compile(r'authentication failure.*ruser=(\S+).*host=(\d+\.\d+\.\d+\.\d+)'),
            'sudo_failure': re.compile(r'sudo:.*authentication failure.*user=(\S+).*host=(\S+)'),
            'time_stamp': re.compile(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'),
        }
        
    def parse_log_line(self, line: str, source: str = 'syslog') -> Dict:
        """
        Parse a single log line and extract security-relevant information
        
        Args:
            line: Single log line string
            source: Type of log (syslog, auth.log, etc.)
            
        Returns:
            Dictionary with parsed information
        """
        result = {
            'timestamp': None,
            'event_type': None,
            'username': None,
            'ip_address': None,
            'raw_line': line.strip()
        }
        
        # Extract timestamp (simplified for common log formats)
        time_match = self.patterns['time_stamp'].search(line)
        if time_match:
            current_year = datetime.now().year
            try:
                timestamp_str = f"{time_match.group(1)} {current_year}"
                result['timestamp'] = datetime.strptime(timestamp_str, "%b %d %H:%M:%S %Y")
            except:
                result['timestamp'] = datetime.now()
        else:
            result['timestamp'] = datetime.now()
        
        # Check for failed SSH attempts
        ssh_fail = self.patterns['failed_ssh'].search(line)
        if ssh_fail:
            result['event_type'] = 'FAILED_SSH'
            result['username'] = ssh_fail.group(1)
            result['ip_address'] = ssh_fail.group(2)
            return result
        
        # Check for invalid user attempts
        invalid_user = self.patterns['invalid_user'].search(line)
        if invalid_user:
            result['event_type'] = 'INVALID_USER'
            result['username'] = invalid_user.group(1)
            result['ip_address'] = invalid_user.group(2)
            return result
        
        # Check for authentication failures
        auth_fail = self.patterns['auth_failure'].search(line)
        if auth_fail:
            result['event_type'] = 'AUTH_FAILURE'
            result['username'] = auth_fail.group(1)
            result['ip_address'] = auth_fail.group(2)
            return result
        
        return result
    
    def analyze_brute_force(self) -> List[Dict]:
        """
        Detect brute force attempts based on failed login frequency
        
        Returns:
            List of dictionaries containing brute force detections
        """
        brute_force_attempts = []
        
        for ip, attempts in self.failed_logins.items():
            if len(attempts) >= self.threshold:
                # Sort attempts by timestamp
                attempts.sort(key=lambda x: x['timestamp'])
                
                # Check time-windowed attacks
                for i in range(len(attempts)):
                    window_attempts = 1
                    for j in range(i + 1, len(attempts)):
                        time_diff = (attempts[j]['timestamp'] - attempts[i]['timestamp']).total_seconds() / 60
                        if time_diff <= self.time_window:
                            window_attempts += 1
                        else:
                            break
                    
                    if window_attempts >= self.threshold:
                        detection = {
                            'ip': ip,
                            'total_attempts': len(attempts),
                            'attempts_in_window': window_attempts,
                            'time_window_minutes': self.time_window,
                            'first_attempt': attempts[i]['timestamp'],
                            'last_attempt': attempts[i + window_attempts - 1]['timestamp'] if window_attempts > 1 else attempts[i]['timestamp'],
                            'usernames_tried': list(set([a['username'] for a in attempts[i:i+window_attempts]]))
                        }
                        brute_force_attempts.append(detection)
                        break
        
        return brute_force_attempts
    
    def detect_user_enumeration(self) -> List[Dict]:
        """
        Detect attempts to enumerate valid usernames
        
        Returns:
            List of IPs trying to enumerate users
        """
        enumeration_results = []
        
        for ip, attempts in self.user_enumeration.items():
            unique_users = set(attempts)
            if len(unique_users) > 5:  # Threshold for enumeration attempts
                enumeration_results.append({
                    'ip': ip,
                    'unique_usernames_tried': len(unique_users),
                    'total_attempts': len(attempts),
                    'usernames': list(unique_users)[:20]  # Show first 20
                })
        
        return enumeration_results
    
    def process_log_file(self, log_file: Path) -> None:
        """
        Process a log file and collect security events
        
        Args:
            log_file: Path to the log file
        """
        print(f"[+] Processing {log_file}...")
        
        try:
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as file:
                for line_num, line in enumerate(file, 1):
                    parsed = self.parse_log_line(line)
                    
                    if parsed['event_type'] in ['FAILED_SSH', 'AUTH_FAILURE']:
                        if parsed['ip_address']:
                            self.failed_logins[parsed['ip_address']].append({
                                'timestamp': parsed['timestamp'],
                                'username': parsed['username'],
                                'line_num': line_num
                            })
                    
                    if parsed['event_type'] == 'INVALID_USER' and parsed['ip_address']:
                        self.user_enumeration[parsed['ip_address']].append(parsed['username'])
                        
        except Exception as e:
            print(f"[-] Error processing {log_file}: {e}")
    
    def generate_report(self, output_format: str = 'text') -> str:
        """
        Generate a comprehensive security report
        
        Args:
            output_format: 'text', 'json', or 'csv'
            
        Returns:
            Formatted report as string
        """
        brute_force = self.analyze_brute_force()
        enumeration = self.detect_user_enumeration()
        
        if output_format == 'json':
            report = {
                'summary': {
                    'total_failed_attempts': sum(len(attempts) for attempts in self.failed_logins.values()),
                    'unique_attacking_ips': len(self.failed_logins),
                    'brute_force_detections': len(brute_force),
                    'enumeration_detections': len(enumeration)
                },
                'brute_force_attacks': brute_force,
                'user_enumeration': enumeration,
                'top_offenders': self.get_top_offenders(10)
            }
            return json.dumps(report, indent=2, default=str)
        
        elif output_format == 'csv':
            output = []
            # Brute force CSV
            output.append("Type,IP,Total_Attempts,First_Attempt,Last_Attempt,Usernames")
            for bf in brute_force:
                output.append(f"BruteForce,{bf['ip']},{bf['total_attempts']},{bf['first_attempt']},{bf['last_attempt']},{';'.join(bf['usernames_tried'])}")
            for enum in enumeration:
                output.append(f"Enumeration,{enum['ip']},{enum['total_attempts']},N/A,N/A,{';'.join(enum['usernames'][:5])}")
            return '\n'.join(output)
        
        else:  # text format
            report = []
            report.append("=" * 80)
            report.append("SECURITY LOG ANALYSIS REPORT")
            report.append("=" * 80)
            
            # Summary
            report.append("\n[SUMMARY]")
            report.append(f"Total failed login attempts: {sum(len(attempts) for attempts in self.failed_logins.values())}")
            report.append(f"Unique attacking IP addresses: {len(self.failed_logins)}")
            report.append(f"Brute force attacks detected: {len(brute_force)}")
            report.append(f"User enumeration attempts: {len(enumeration)}")
            
            # Brute Force Detections
            if brute_force:
                report.append("\n[BRUTE FORCE ATTACKS DETECTED]")
                for bf in brute_force:
                    report.append(f"\n  IP: {bf['ip']}")
                    report.append(f"  Total attempts: {bf['total_attempts']}")
                    report.append(f"  Attempts in {bf['time_window_minutes']} minutes: {bf['attempts_in_window']}")
                    report.append(f"  Time range: {bf['first_attempt']} to {bf['last_attempt']}")
                    report.append(f"  Usernames attempted: {', '.join(bf['usernames_tried'][:10])}")
                    if len(bf['usernames_tried']) > 10:
                        report.append(f"    ... and {len(bf['usernames_tried']) - 10} more")
            
            # User Enumeration
            if enumeration:
                report.append("\n[USER ENUMERATION ATTEMPTS]")
                for enum in enumeration:
                    report.append(f"\n  IP: {enum['ip']}")
                    report.append(f"  Unique usernames tried: {enum['unique_usernames_tried']}")
                    report.append(f"  Total attempts: {enum['total_attempts']}")
                    report.append(f"  Example usernames: {', '.join(enum['usernames'][:5])}")
            
            # Top attacking IPs
            report.append("\n[TOP ATTACKING IP ADDRESSES]")
            top_ips = self.get_top_offenders(10)
            for ip, count in top_ips:
                report.append(f"  {ip}: {count} attempts")
            
            # Recommendations
            report.append("\n[RECOMMENDATIONS]")
            if brute_force:
                report.append("  • Block the identified brute force IP addresses using firewall rules")
                report.append("  • Implement rate limiting for authentication attempts")
                report.append("  • Consider using fail2ban or similar tools")
            if enumeration:
                report.append("  • Disable or rename default system accounts")
                report.append("  • Implement account lockout policies")
            report.append("  • Enable multi-factor authentication where possible")
            report.append("  • Review and update password policies")
            
            report.append("\n" + "=" * 80)
            return '\n'.join(report)
    
    def get_top_offenders(self, limit: int = 10) -> List[Tuple[str, int]]:
        """
        Get top attacking IPs based on failed attempts
        
        Args:
            limit: Number of top offenders to return
            
        Returns:
            List of (IP, count) tuples
        """
        return Counter(self.failed_logins.keys()).most_common(limit)


def main():
    """Main function with command-line interface"""
    parser = argparse.ArgumentParser(
        description='Advanced Security Log Analyzer for Cybersecurity Portfolio',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python log_analyzer.py -l /var/log/auth.log
  python log_analyzer.py -d /var/log/ -t 5 -w 30
  python log_analyzer.py -l secure.log -f json -o report.json
  python log_analyzer.py -l auth.log -f csv -o report.csv
        """
    )
    
    parser.add_argument('-l', '--log-file', type=Path, help='Path to specific log file')
    parser.add_argument('-d', '--log-directory', type=Path, help='Directory containing log files')
    parser.add_argument('-t', '--threshold', type=int, default=10, 
                       help='Failed attempts threshold for brute force detection (default: 10)')
    parser.add_argument('-w', '--window', type=int, default=60,
                       help='Time window in minutes for attack detection (default: 60)')
    parser.add_argument('-f', '--format', choices=['text', 'json', 'csv'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('-o', '--output', type=Path, help='Output file path')
    
    args = parser.parse_args()
    
    # Validate inputs
    if not args.log_file and not args.log_directory:
        parser.error("Either --log-file or --log-directory is required")
    
    # Initialize analyzer
    analyzer = SecurityLogAnalyzer(threshold=args.threshold, time_window=args.window)
    
    # Process log files
    if args.log_file and args.log_file.exists():
        analyzer.process_log_file(args.log_file)
    elif args.log_directory and args.log_directory.exists():
        for log_file in args.log_directory.glob("*.log"):
            analyzer.process_log_file(log_file)
    else:
        print("[-] No valid log files found")
        return
    
    # Generate report
    report = analyzer.generate_report(output_format=args.format)
    
    # Output report
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"[+] Report saved to {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()