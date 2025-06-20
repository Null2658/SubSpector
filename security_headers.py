import json
import os
from datetime import datetime
import requests
import urllib3
from typing import Dict, List, Tuple, Any
import logging
from logger import log_security_event
import time
import whois
import dns.resolver

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Define required security headers with their importance levels
REQUIRED_SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'risk_level': 'Critical',
        'weight': 20,  # 20 points
        'recommendation': 'Set max-age to at least 31536000 (1 year)',
        'description': 'Forces HTTPS connections'
    },
    'Content-Security-Policy': {
        'risk_level': 'Critical',
        'weight': 20,  # 20 points
        'recommendation': 'Implement a strong CSP policy',
        'description': 'Prevents XSS and other injection attacks'
    },
    'X-Frame-Options': {
        'risk_level': 'High',
        'weight': 15,  # 15 points
        'recommendation': 'Set to DENY or SAMEORIGIN',
        'description': 'Prevents clickjacking attacks'
    },
    'X-Content-Type-Options': {
        'risk_level': 'High',
        'weight': 10,  # 10 points
        'recommendation': 'Set to nosniff',
        'description': 'Prevents MIME type sniffing'
    },
    'X-XSS-Protection': {
        'risk_level': 'Medium',
        'weight': 10,  # 10 points
        'recommendation': 'Set to 1; mode=block',
        'description': 'Enables browser XSS filtering'
    },
    'Referrer-Policy': {
        'risk_level': 'Medium',
        'weight': 10,  # 10 points
        'recommendation': 'Set to strict-origin-when-cross-origin',
        'description': 'Controls referrer information'
    },
    'Permissions-Policy': {
        'risk_level': 'Medium',
        'weight': 10,  # 10 points
        'recommendation': 'Implement a restrictive permissions policy',
        'description': 'Controls browser features and APIs'
    },
    'Cross-Origin-Opener-Policy': {
        'risk_level': 'High',
        'weight': 15,  # 15 points
        'recommendation': 'Set to same-origin',
        'description': 'Prevents cross-origin window attacks'
    },
    'Cross-Origin-Embedder-Policy': {
        'risk_level': 'High',
        'weight': 15,  # 15 points
        'recommendation': 'Set to require-corp',
        'description': 'Prevents cross-origin resource loading'
    },
    'Cross-Origin-Resource-Policy': {
        'risk_level': 'Medium',
        'weight': 10,  # 10 points
        'recommendation': 'Set to same-site',
        'description': 'Controls cross-origin resource loading'
    },
    'Cache-Control': {
        'risk_level': 'Low',
        'weight': 5,  # 5 points
        'recommendation': 'Set appropriate caching directives',
        'description': 'Controls caching behavior'
    }
}

class SecurityHeadersChecker:
    def __init__(self):
        """Initialize the security headers checker"""
        self.headers_dir = os.path.join('logs', 'headers')
        os.makedirs(self.headers_dir, exist_ok=True)
        
        # Setup logger for security headers
        self.logger = logging.getLogger('security_headers')
        self.logger.setLevel(logging.INFO)
        
        # Add file handler with simple formatter
        headers_handler = logging.FileHandler(os.path.join(self.headers_dir, 'headers.log'), encoding='utf-8')
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        headers_handler.setFormatter(formatter)
        self.logger.addHandler(headers_handler)

    def _get_headers_file_path(self, domain: str) -> str:
        """Get the path for the domain's headers log file"""
        return os.path.join(self.headers_dir, f'headers_{domain}.json')

    def _load_previous_headers(self, domain: str) -> Dict:
        """Load previous headers for the domain"""
        file_path = self._get_headers_file_path(domain)
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return {}
        return {}

    def _save_headers(self, domain: str, headers: Dict, missing: List[str], security_score: int) -> None:
        """Save current headers and security information"""
        file_path = self._get_headers_file_path(domain)
        data = {
            'last_check': datetime.now().isoformat(),
            'headers': headers,
            'missing_security_headers': missing,
            'security_score': security_score,
            'check_time': datetime.now().isoformat()
        }
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)

    def _calculate_security_score(self, present_headers: List[str]) -> int:
        """Calculate security score based on present headers"""
        total_headers = len(REQUIRED_SECURITY_HEADERS)
        present_count = len(present_headers)
        return int((present_count / total_headers) * 100)

    def check_security_headers(self, domain: str) -> Tuple[Dict, List[str], int]:
        """
        Check HTTP security headers for the domain
        Returns: (headers, missing_headers, security_score)
        """
        missing_headers = []
        headers = {}
        
        try:
            # Try to connect to the site
            response = requests.get(f'https://{domain}', timeout=10, 
                                 allow_redirects=True, verify=False)
            headers = dict(response.headers)
            
            # Calculate security score
            security_score = self._calculate_security_score([h for h in REQUIRED_SECURITY_HEADERS if h in headers])
            
            # Check missing headers
            for header in REQUIRED_SECURITY_HEADERS:
                if header not in headers:
                    missing_headers.append(header)
                    # Log missing security header with proper risk level
                    log_security_event(
                        self.logger,
                        "header_missing",
                        domain,
                        f"Missing {header}: {REQUIRED_SECURITY_HEADERS[header]['description']}",
                        risk_level=REQUIRED_SECURITY_HEADERS[header]['risk_level'],
                        recommended_action=REQUIRED_SECURITY_HEADERS[header]['recommendation'],
                        security_score=security_score
                    )
            
            # Log successful check
            self.logger.info(
                f"Security headers check completed for {domain}",
                extra={
                    'domain': domain,
                    'score': security_score,
                    'missing_headers': ', '.join(missing_headers),
                    'present_headers': ', '.join([h for h in REQUIRED_SECURITY_HEADERS if h in headers]),
                    'all_headers': json.dumps(headers, indent=2)
                }
            )
            
            # Save report to JSON file
            self._save_headers(domain, headers, missing_headers, security_score)
            
        except requests.exceptions.SSLError as e:
            log_security_event(
                self.logger,
                "ssl_error",
                domain,
                str(e),
                risk_level="High",
                recommended_action="Fix SSL certificate issues",
                security_score=0
            )
            return {}, ['SSL Error'], 0
        except requests.exceptions.RequestException as e:
            log_security_event(
                self.logger,
                "connection_error",
                domain,
                str(e),
                risk_level="Medium",
                recommended_action="Check server availability and network connectivity",
                security_score=0
            )
            return {}, ['Connection Error'], 0
        
        return headers, missing_headers, security_score

    def get_headers_report(self, domain: str) -> Dict:
        """Get comprehensive security headers report for a domain"""
        report = {
            'domain': domain,
            'scan_time': datetime.now().isoformat(),
            'connection_success': False,
            'status_code': None,
            'response_time': None,
            'server': None,
            'redirect_url': None,
            'headers_present': {},
            'headers_missing': [],
            'security_score': 0,
            'whois_info': {},
            'dns_info': {},
            'ssl_issues': None
        }
        
        # First try with SSL verification
        try:
            start_time = time.time()
            response = requests.get(f'https://{domain}', 
                                 timeout=10, 
                                 verify=True,
                                 allow_redirects=True)
            end_time = time.time()
            
            report['connection_success'] = True
            report['status_code'] = response.status_code
            report['response_time'] = round((end_time - start_time) * 1000, 2)
            report['server'] = response.headers.get('Server', 'Unknown')
            
            if response.history:
                report['redirect_url'] = response.url
            
            # Check security headers with value validation
            headers = response.headers
            for header, required_info in REQUIRED_SECURITY_HEADERS.items():
                if header in headers:
                    value = headers[header]
                    # Validate header value
                    is_valid = self._validate_header_value(header, value)
                    report['headers_present'][header] = {
                        'value': value,
                        'valid': is_valid,
                        'weight': required_info['weight'],
                        'risk_level': required_info['risk_level'],
                        'recommendation': required_info['recommendation'],
                        'description': required_info['description']
                    }
                else:
                    report['headers_missing'].append({
                        'name': header,
                        'risk_level': required_info['risk_level'],
                        'weight': required_info['weight'],
                        'recommendation': required_info['recommendation'],
                        'description': required_info['description']
                    })
            
            # Calculate security score with new weighting system
            score = 0
            if report['connection_success']:
                score += 20  # 20 points for HTTPS support
            
            # Add points for present headers
            for header_info in report['headers_present'].values():
                if header_info['valid']:
                    score += header_info['weight']  # Full points for valid headers
                else:
                    score += header_info['weight'] // 2  # Half points for invalid headers
            
            report['security_score'] = min(score, 100)
            
        except requests.exceptions.SSLError:
            # SSL verification failed, try without verification to check if site is up
            try:
                start_time = time.time()
                response = requests.get(f'https://{domain}', 
                                     timeout=10, 
                                     verify=False,  # Disable SSL verification
                                     allow_redirects=True)
                end_time = time.time()
                
                report['connection_success'] = True
                report['status_code'] = response.status_code
                report['response_time'] = round((end_time - start_time) * 1000, 2)
                report['server'] = response.headers.get('Server', 'Unknown')
                report['ssl_issues'] = "SSL certificate issues (expired, self-signed, or invalid)"
                
                if response.history:
                    report['redirect_url'] = response.url
                
                # Check security headers with value validation
                headers = response.headers
                for header, required_info in REQUIRED_SECURITY_HEADERS.items():
                    if header in headers:
                        value = headers[header]
                        # Validate header value
                        is_valid = self._validate_header_value(header, value)
                        report['headers_present'][header] = {
                            'value': value,
                            'valid': is_valid,
                            'weight': required_info['weight'],
                            'risk_level': required_info['risk_level'],
                            'recommendation': required_info['recommendation'],
                            'description': required_info['description']
                        }
                    else:
                        report['headers_missing'].append({
                            'name': header,
                            'risk_level': required_info['risk_level'],
                            'weight': required_info['weight'],
                            'recommendation': required_info['recommendation'],
                            'description': required_info['description']
                        })
                
                # Calculate security score (reduced due to SSL issues)
                score = 0
                if report['connection_success']:
                    score += 5  # Only 5 points for HTTPS with SSL issues
                
                # Add points for present headers
                for header_info in report['headers_present'].values():
                    if header_info['valid']:
                        score += header_info['weight']  # Full points for valid headers
                    else:
                        score += header_info['weight'] // 2  # Half points for invalid headers
                
                report['security_score'] = min(score, 100)
                
            except requests.exceptions.ConnectionError:
                self.logger.error(f"Connection error for {domain}")
                report['connection_error'] = "Connection failed"
            except requests.exceptions.Timeout:
                self.logger.error(f"Connection timeout for {domain}")
                report['timeout_error'] = "Connection timed out"
            except Exception as e:
                self.logger.error(f"Error checking security headers for {domain}: {str(e)}")
                report['error'] = str(e)
                
        except requests.exceptions.ConnectionError:
            self.logger.error(f"Connection error for {domain}")
            report['connection_error'] = "Connection failed"
        except requests.exceptions.Timeout:
            self.logger.error(f"Connection timeout for {domain}")
            report['timeout_error'] = "Connection timed out"
        except Exception as e:
            self.logger.error(f"Error checking security headers for {domain}: {str(e)}")
            report['error'] = str(e)
        
        # Get WHOIS information if connection was successful
        if report['connection_success']:
            try:
                whois_info = whois.whois(domain)
                report['whois_info'] = {
                    'registrar': whois_info.registrar,
                    'creation_date': whois_info.creation_date,
                    'expiration_date': whois_info.expiration_date,
                    'nameservers': whois_info.name_servers
                }
            except Exception as e:
                self.logger.error(f"Error getting WHOIS info for {domain}: {str(e)}")
            
            # Get DNS information
            try:
                dns_info = dns.resolver.resolve(domain, 'A')
                report['dns_info'] = {
                    'a_records': [str(r) for r in dns_info],
                    'geo_info': self._get_geo_info(str(dns_info[0]))
                }
            except Exception as e:
                self.logger.error(f"Error getting DNS info for {domain}: {str(e)}")
        
        return report

    def _validate_header_value(self, header: str, value: str) -> bool:
        """Validate security header values"""
        try:
            if header == 'Strict-Transport-Security':
                # Check for max-age directive
                return 'max-age=' in value.lower()
            
            elif header == 'Content-Security-Policy':
                # Basic CSP validation
                return len(value) > 0 and ';' in value
            
            elif header == 'X-Frame-Options':
                # Check for valid values
                return value.lower() in ['deny', 'sameorigin']
            
            elif header == 'X-Content-Type-Options':
                # Should be nosniff
                return value.lower() == 'nosniff'
            
            elif header == 'X-XSS-Protection':
                # Check for valid values
                return value.lower() in ['0', '1', '1; mode=block']
            
            elif header == 'Referrer-Policy':
                # Check for valid values
                valid_values = ['no-referrer', 'no-referrer-when-downgrade', 'origin', 
                              'origin-when-cross-origin', 'same-origin', 'strict-origin',
                              'strict-origin-when-cross-origin', 'unsafe-url']
                return value.lower() in valid_values
            
            elif header == 'Permissions-Policy':
                # Basic validation
                return len(value) > 0 and '=' in value
            
            elif header == 'Cache-Control':
                # Basic validation
                return len(value) > 0
            
            return True  # Default to True for other headers
            
        except Exception as e:
            self.logger.error(f"Error validating header {header}: {str(e)}")
            return False

    def _get_geo_info(self, ip: str) -> Dict:
        """Get geographic information for an IP address"""
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'city': data.get('city'),
                    'country': data.get('country'),
                    'isp': data.get('isp')
                }
        except Exception as e:
            self.logger.error(f"Error getting geo info for {ip}: {str(e)}")
        return {} 

    def analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze security headers and return results"""
        results = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'headers_present': [],
            'headers_missing': [],
            'security_score': 0,
            'total_weight': 0,
            'achieved_weight': 0
        }
        
        for header in REQUIRED_SECURITY_HEADERS.values():
            if header['name'] in headers:
                results['headers_present'].append(header)
                results['achieved_weight'] += header['weight']
            else:
                results['headers_missing'].append(header)
            results['total_weight'] += header['weight']
        
        # Calculate security score
        if results['total_weight'] > 0:
            results['security_score'] = (results['achieved_weight'] / results['total_weight']) * 100
        
        return results 