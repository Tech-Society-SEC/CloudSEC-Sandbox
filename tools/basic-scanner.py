#!/usr/bin/env python3
"""
Basic Web Vulnerability Scanner for CloudSec Sandbox
Educational purposes only - scans local applications
"""

import requests
import sys
from urllib.parse import urljoin

class BasicScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        
    def check_sql_injection(self, path):
        """Basic SQL injection detection"""
        payloads = ["'", "' OR '1'='1", "' UNION SELECT 1--"]
        results = []
        
        for payload in payloads:
            try:
                url = urljoin(self.base_url, path)
                params = {'id': payload}
                response = self.session.get(url, params=params)
                
                if any(error in response.text.lower() for error in 
                       ['mysql', 'sql syntax', 'warning: mysql']):
                    results.append(f"Potential SQL injection: {payload}")
                    
            except Exception as e:
                print(f"Error testing {payload}: {e}")
                
        return results
    
    def scan_common_paths(self):
        """Scan for common vulnerable paths"""
        paths = [
            '/DVWA/vulnerabilities/sqli/',
            '/DVWA/vulnerabilities/xss_r/',
            '/DVWA/vulnerabilities/upload/',
        ]
        
        print("🔍 CloudSec Sandbox Basic Scanner")
        print("=" * 40)
        
        for path in paths:
            print(f"\n📍 Scanning: {path}")
            sql_results = self.check_sql_injection(path)
            for result in sql_results:
                print(f"  🚨 {result}")
                
        print("\n✅ Scan complete! Remember: Only test on your own systems.")

if __name__ == "__main__":
    scanner = BasicScanner("http://localhost")
    scanner.scan_common_paths()
