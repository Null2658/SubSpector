#!/usr/bin/env python3
"""
SubSpector - Advanced Subdomain Monitoring & Security Analysis Tool
Author: SubSpector Team
Version: 2.0.0
License: MIT

A comprehensive tool for subdomain discovery, monitoring, and security analysis.
Features include real-time monitoring, security headers analysis, subdomain takeover detection,
WHOIS monitoring, and comprehensive reporting.
"""

import os
import sys
import json
import time
import random
import argparse
import subprocess
from datetime import datetime, timedelta
from termcolor import colored
import whois
import requests
import csv
import ssl
import socket
import subprocess
from colorama import init, Fore, Style
import dns.resolver
import logging
from typing import List, Dict, Any, Union
from logger import log_with_data, terminal_logger
from OpenSSL import crypto
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from OpenSSL import SSL
import platform
import glob
import gzip

# Initialize colorama
init()

# Color codes
PURPLE = '\033[95m'
LIGHT_PURPLE = '\033[94m'
DARK_PURPLE = '\033[35m'
RESET = '\033[0m'

def print_banner():
    """Print the SubSpector banner with purple color scheme and features below the box"""
    banner = f"""
{Colors.PURPLE}╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  {Colors.LIGHT_PURPLE}███████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗ ██████╗████████╗ ██████╗ ██████╗{Colors.PURPLE}  ║
║  {Colors.LIGHT_PURPLE}██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝╚══██╔══╝██╔═══██╗██╔══██╗{Colors.PURPLE} ║
║  {Colors.LIGHT_PURPLE}███████╗██║   ██║██████╔╝███████╗██████╔╝█████╗  ██║        ██║   ██║   ██║██████╔╝{Colors.PURPLE} ║
║  {Colors.LIGHT_PURPLE}╚════██║██║   ██║██╔══██╗╚════██║██╔═══╝ ██╔══╝  ██║        ██║   ██║   ██║██╔══██╗{Colors.PURPLE} ║
║  {Colors.LIGHT_PURPLE}███████║╚██████╔╝██████╔╝███████║██║     ███████╗╚██████╗   ██║   ╚██████╔╝██║  ██║{Colors.PURPLE} ║
║  {Colors.LIGHT_PURPLE}╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝{Colors.PURPLE} ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}
"""
    features = f"""
{Fore.LIGHTMAGENTA_EX}🛡️  Advanced Subdomain Monitoring & Security Analysis Tool
🔍  Comprehensive Subdomain Discovery & Enumeration
🔒  Security Headers & SSL Certificate Analysis
📊  Real-time Monitoring & Status Tracking
📈  Detailed Statistics & Performance Metrics
🛡️  Security Assessment & Risk Analysis{Style.RESET_ALL}
"""
    print(banner + "\n" + features)
    log_with_data(terminal_logger, logging.INFO, "SubSpector Banner", {"type": "banner", "content": banner, "features": features})

def print_section_header(text: str):
    """Print a section header with purple color scheme"""
    header = f"\n{Colors.PURPLE}╔{'═' * (len(text) + 4)}╗\n║  {Colors.LIGHT_PURPLE}{text}{Colors.PURPLE}  ║\n╚{'═' * (len(text) + 4)}╝{Colors.RESET}\n"
    print(header)
    log_with_data(terminal_logger, logging.INFO, f"Section Header: {text}", {"type": "section_header", "content": header})

def print_subsection_header(text: str):
    """Print a subsection header with light purple color scheme"""
    header = f"\n{Colors.LIGHT_PURPLE}╔{'═' * (len(text) + 4)}╗\n║  {text}  ║\n╚{'═' * (len(text) + 4)}╝{Colors.RESET}\n"
    print(header)
    log_with_data(terminal_logger, logging.INFO, f"Subsection Header: {text}", {"type": "subsection_header", "content": header})

def print_info(*args, indent: int = 2, value_white: bool = False):
    """Print information with proper indentation. If value_white is True, print values in white."""
    if value_white and len(args) >= 2:
        # Assume: label, value, [status]
        label = str(args[0])
        value = str(args[1])
        rest = " ".join(str(arg) for arg in args[2:])
        info = " " * indent + f"{Fore.LIGHTMAGENTA_EX}{label}{Style.RESET_ALL} {Fore.WHITE}{value}{Style.RESET_ALL} {rest}"
    else:
        info = " " * indent + " ".join(str(arg) for arg in args)
        info = f"{Fore.LIGHTMAGENTA_EX}{info}{Style.RESET_ALL}"
    print(info)
    log_with_data(terminal_logger, logging.INFO, info, {"type": "info", "indent": indent})

# Import SubSpector modules
from scanner import SubdomainScanner
from security_headers import SecurityHeadersChecker, REQUIRED_SECURITY_HEADERS
from logger import setup_logger
from config import Config

# ANSI color codes for cross-platform compatibility
class Colors:
    """ANSI color codes for terminal output"""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    PURPLE = "\033[38;5;183m"  # Softer light purple
    LIGHT_PURPLE = "\033[38;5;189m"  # Even lighter
    DARK_PURPLE = "\033[38;5;104m"  # Softer dark purple

def check_dependencies():
    """Check if required dependencies are available"""
    print(f"{Colors.CYAN}🔍 Checking dependencies...{Colors.RESET}")
    
    # Check subfinder - support both Windows and Linux
    system = platform.system().lower()
    
    if system == "windows":
        subfinder_exe = "subfinder.exe"
        subfinder_local = os.path.join("subfinder", subfinder_exe)
        subfinder_check = "subfinder -version > nul 2>&1"
    else:
        subfinder_exe = "subfinder"
        subfinder_local = os.path.join("subfinder", subfinder_exe)
        subfinder_check = "subfinder -version > /dev/null 2>&1"
    
    if os.path.exists(subfinder_local):
        print(f"{Colors.GREEN}  ✅ Subfinder: Found (local){Colors.RESET}")
    elif os.system(subfinder_check) == 0:
        print(f"{Colors.GREEN}  ✅ Subfinder: Found (system PATH){Colors.RESET}")
    else:
        print(f"{Colors.RED}  ❌ Subfinder: Not found{Colors.RESET}")
        if system == "windows":
            print(f"{Colors.YELLOW}     Please install subfinder or place subfinder.exe in ./subfinder/{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}     Please install subfinder or place subfinder binary in ./subfinder/{Colors.RESET}")
        return False
    
    # Check Python modules
    required_modules = {
        'requests': 'requests',
        'whois': 'whois', 
        'termcolor': 'termcolor',
        'dnspython': 'dns'
    }
    for display_name, import_name in required_modules.items():
        try:
            __import__(import_name)
            print(f"{Colors.GREEN}  ✅ {display_name}: Available{Colors.RESET}")
        except ImportError:
            print(f"{Colors.RED}  ❌ {display_name}: Missing{Colors.RESET}")
            print(f"{Colors.YELLOW}     Run: pip install {display_name}{Colors.RESET}")
            return False
    
    print(f"{Colors.GREEN}✅ All dependencies satisfied{Colors.RESET}\n")
    return True

class SubSpector:
    """Main SubSpector class"""
    
    def __init__(self, domain, mode='monitor'):
        """Initialize SubSpector"""
        self.domain = domain
        self.mode = mode
        self.config = Config()
        self.scanner = SubdomainScanner(self.domain)
        self.security_checker = SecurityHeadersChecker()
        self.required_headers = REQUIRED_SECURITY_HEADERS  # Store headers list
        self.logger = setup_logger()
        self.results = {}
        
        # Create reports directory if it doesn't exist
        if not os.path.exists('reports'):
            os.makedirs('reports')
        
        # Create log directories and files FIRST
        self.log_dirs = {
            'security': 'logs/security',
            'whois': 'logs/whois',
            'stats': 'logs/stats',
            'status': 'logs/status',
            'updown': 'logs/updown'
        }
        for dir_path in self.log_dirs.values():
            os.makedirs(dir_path, exist_ok=True)
        os.makedirs('logs/headers', exist_ok=True)
        os.makedirs('logs/terminal', exist_ok=True)
        os.makedirs('reports', exist_ok=True)

        self.log_files = {
            'security': os.path.join(self.log_dirs['security'], f'security_{domain}.json'),
            'whois': os.path.join(self.log_dirs['whois'], f'whois_{domain}.json'),
            'stats': os.path.join(self.log_dirs['stats'], f'stats_{domain}.json'),
            'status': os.path.join(self.log_dirs['status'], f'status_{domain}.json'),
            'updown': os.path.join(self.log_dirs['updown'], f'updown_{domain}.json')
        }
        for log_file in self.log_files.values():
            if not os.path.exists(log_file):
                with open(log_file, 'w', encoding='utf-8') as f:
                    json.dump({'entries': []}, f, indent=2)

        # Log management settings (must be before cleanup calls)
        self.max_log_size = 10 * 1024 * 1024  # 10MB
        self.max_entries = 1000
        self.cleanup_old_logs = True

        # Now safe to do log management
        self._cleanup_old_logs()
        self._cleanup_empty_logs()
        self._compress_old_logs()

        # Check if OpenSSL is available for better SSL certificate details
        self.openssl_available = self._check_openssl_availability()

        self.output_file = f"reports/analysis_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    def _log_security(self, data, level='INFO'):
        """Log security information in JSON format with improved error handling and memory management"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            # Handle different data structures
            if isinstance(data, dict):
                # If data is already a complete security report
                log_entry = {
                    'timestamp': timestamp,
                    'level': level,
                    'domain': self.domain,
                    'data': data
                }
            else:
                # If data is just a string or other type, create a simple entry
                log_entry = {
                    'timestamp': timestamp,
                    'level': level,
                    'domain': self.domain,
                    'data': {
                        'message': str(data),
                        'type': 'info'
                    }
                }
            
            # Read current log if exists
            try:
                with open(self.log_files['security'], 'r', encoding='utf-8') as f:
                    log_data = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                log_data = {'entries': []}
            
            # Add new entry
            log_data['entries'].append(log_entry)
            
            # Keep only last 1000 entries to manage memory
            if len(log_data['entries']) > 1000:
                log_data['entries'] = log_data['entries'][-1000:]
            
            # Save updated log
            with open(self.log_files['security'], 'w', encoding='utf-8') as f:
                json.dump(log_data, f, indent=2, ensure_ascii=False, default=str)
            
        except Exception as e:
            # Use a simple fallback logging to avoid infinite recursion
            try:
                with open(self.log_files['security'], 'a', encoding='utf-8') as f:
                    error_entry = {
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'level': 'ERROR',
                        'domain': self.domain,
                        'data': {
                            'error': f'Error logging security data: {str(e)}',
                            'original_data': str(data)
                        }
                    }
                    f.write(json.dumps(error_entry, ensure_ascii=False, default=str) + '\n')
            except:
                pass  # If even this fails, just continue

    def _log_whois(self, data, level='INFO'):
        """Log WHOIS information in JSON format"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'domain': self.domain,
            'data': data
        }
        
        try:
            with open(self.log_files['whois'], 'r', encoding='utf-8') as f:
                log_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            log_data = {'entries': []}
        
        log_data['entries'].append(log_entry)
        
        with open(self.log_files['whois'], 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False, default=str)

    def _log_stats(self, total: Union[int, dict], active: int = 0, inactive: int = 0, avg_response: float = 0.0, avg_security: float = 0.0):
        """Log statistics to JSON file."""
        try:
            # Convert total to integer if it's a dictionary
            if isinstance(total, dict):
                total = total.get('total_subdomains', 0)
            else:
                total = int(total)
            
            # Ensure all values are of correct type
            active = int(active)
            inactive = int(inactive)
            avg_response = float(avg_response)
            avg_security = float(avg_security)
            
            # Calculate missing values if needed
            if active == 0 and inactive == 0 and total > 0:
                active = total
                inactive = 0
            
            # Create stats directory if it doesn't exist
            stats_dir = os.path.join('logs', 'stats')
            os.makedirs(stats_dir, exist_ok=True)
            
            # Get current date for filename
            current_date = datetime.now().strftime('%Y-%m-%d')
            stats_file = os.path.join(stats_dir, f'stats_{current_date}.json')
            
            # Read existing stats if file exists
            stats = []
            if os.path.exists(stats_file):
                try:
                    with open(stats_file, 'r') as f:
                        stats = json.load(f)
                        if not isinstance(stats, list):
                            stats = []
                except json.JSONDecodeError:
                    stats = []
            
            # Add new stats entry
            stats.append({
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'total': total,
                'active': active,
                'inactive': inactive,
                'avg_response': avg_response,
                'avg_security': avg_security
            })
            
            # Keep only last 1000 entries
            stats = stats[-1000:]
            
            # Save updated stats
            with open(stats_file, 'w') as f:
                json.dump(stats, f, indent=2, default=str)
                
        except Exception as e:
            self.logger.error(f"Error logging stats: {str(e)}")
            self.logger.error(f"Stats data: total={total}, active={active}, inactive={inactive}, avg_response={avg_response}, avg_security={avg_security}")

    def _log_status(self, data, level='INFO'):
        """Log service status in JSON format"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'domain': self.domain,
            'data': data
        }
        
        try:
            with open(self.log_files['status'], 'r', encoding='utf-8') as f:
                log_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            log_data = {'entries': []}
        
        log_data['entries'].append(log_entry)
        
        with open(self.log_files['status'], 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False, default=str)

    def _log_updown(self, data, level='INFO'):
        """Log availability status in JSON format"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            'timestamp': timestamp,
            'level': level,
            'domain': self.domain,
            'data': data
        }
        
        try:
            with open(self.log_files['updown'], 'r', encoding='utf-8') as f:
                log_data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            log_data = {'entries': []}
        
        log_data['entries'].append(log_entry)
        
        with open(self.log_files['updown'], 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False, default=str)
    
    def monitor_mode(self, interval=300):
        """Monitor mode implementation without notifications"""
        print(f"\n{Colors.CYAN}🔍 Starting monitoring for {self.domain}{Colors.RESET}")
        print(f"{Colors.YELLOW}Monitoring interval: {interval} seconds{Colors.RESET}")
        
        try:
            while True:
                self._run_monitoring_cycle()
                time.sleep(interval)
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}Monitoring stopped by user{Colors.RESET}")
        except Exception as e:
            print(f"\n{Colors.RED}Error in monitoring: {str(e)}{Colors.RESET}")

    def _run_monitoring_cycle(self):
        """Run a single monitoring cycle without notifications"""
        try:
            # Get current subdomains
            current_subs = set(self.scanner.scan())
            
            # Check status and security
            for subdomain in current_subs:
                self._check_subdomain_status(subdomain)
                self._check_security(subdomain)
            
            # Log statistics
            self._log_stats(len(current_subs))
            
        except Exception as e:
            print(f"{Colors.RED}Error in monitoring cycle: {str(e)}{Colors.RESET}")

    def _check_takeover(self, subdomain):
        """Check for subdomain takeover vulnerabilities with improved security"""
        try:
            # Validate input
            if not isinstance(subdomain, str) or not subdomain:
                raise ValueError("Invalid subdomain")
            
            # Check DNS records with improved timeout handling
            try:
                # Set DNS resolver timeout for faster checking with fallback
                resolver = dns.resolver.Resolver()
                resolver.timeout = 2  # Reduced timeout
                resolver.lifetime = 2  # Reduced lifetime
                
                # Try multiple DNS servers for better reliability
                try:
                    # First try with default DNS
                    cname_records = resolver.resolve(subdomain, 'CNAME')
                except (dns.resolver.Timeout, dns.exception.Timeout):
                    # If timeout, try with public DNS servers
                    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
                    resolver.timeout = 1.5
                    resolver.lifetime = 1.5
                    cname_records = resolver.resolve(subdomain, 'CNAME')
                
                for record in cname_records:
                    target = str(record.target)
                    
                    # Check for common takeover patterns
                    takeover_patterns = [
                        'github.io',
                        'herokuapp.com',
                        's3.amazonaws.com',
                        'cloudfront.net',
                        'azurewebsites.net',
                        'appspot.com',
                        'firebaseapp.com',
                        'netlify.app',
                        'vercel.app',
                        'pages.dev',
                        'render.com',
                        'railway.app',
                        'fly.dev',
                        'glitch.me'
                    ]
                    
                    for pattern in takeover_patterns:
                        if pattern in target:
                            return {
                                'vulnerable': True,
                                'type': 'CNAME',
                                'target': target,
                                'pattern': pattern,
                                'risk_level': 'High',
                                'recommendation': f'Check if {pattern} service is still in use'
                            }
            
            except dns.resolver.NXDOMAIN:
                return {'vulnerable': False, 'reason': 'Domain does not exist'}
            except dns.resolver.NoAnswer:
                return {'vulnerable': False, 'reason': 'No CNAME record found'}
            except (dns.resolver.Timeout, dns.exception.Timeout):
                return {'vulnerable': False, 'reason': 'DNS timeout - unable to check'}
            except Exception as e:
                # Log error but don't fail the entire scan
                error_msg = str(e)
                if 'timeout' in error_msg.lower() or 'expired' in error_msg.lower():
                    return {'vulnerable': False, 'reason': 'DNS timeout - unable to check'}
                else:
                    return {'vulnerable': False, 'reason': f'DNS error: {error_msg[:50]}...'}
            
            return {'vulnerable': False, 'reason': 'No takeover vulnerability detected'}
            
        except Exception as e:
            # Log error but don't fail the entire scan
            error_msg = str(e)
            if 'timeout' in error_msg.lower() or 'expired' in error_msg.lower():
                return {'vulnerable': False, 'reason': 'DNS timeout - unable to check'}
            else:
                return {'vulnerable': False, 'reason': f'Error: {error_msg[:50]}...'}

    def _calculate_security_score(self, ssl_status, headers, takeover):
        """Calculate security score based on various factors"""
        score = 0
        
        # SSL Certificate Score (40 points)
        if ssl_status and ssl_status.get('valid'):
            days_remaining = ssl_status.get('days_remaining', 0)
            if days_remaining > 30:
                score += 40
            elif days_remaining > 7:
                score += 30
            else:
                score += 20
        
        # Security Headers Score (40 points)
        if headers and isinstance(headers, dict):
            required_headers = {
                'Strict-Transport-Security': 10,
                'X-Frame-Options': 10,
                'X-Content-Type-Options': 10,
                'Content-Security-Policy': 10
            }
            for header, points in required_headers.items():
                if header in headers:
                    score += points

        # Takeover Vulnerability Score (20 points)
        if takeover and not takeover.get('vulnerable'):
            score += 20

        return min(score, 100)

    def _get_header_description(self, header):
        """Get description for security header"""
        descriptions = {
            'Strict-Transport-Security': {
                'description': 'Forces browsers to connect via HTTPS only',
                'recommendation': 'Set max-age to at least 31536000 (1 year)'
            },
            'Content-Security-Policy': {
                'description': 'Prevents unauthorized JavaScript execution and protects against XSS attacks',
                'recommendation': 'Implement a strong CSP policy'
            },
            'X-Frame-Options': {
                'description': 'Prevents site embedding in iframes and protects against Clickjacking attacks',
                'recommendation': 'Set to DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents browser MIME type sniffing',
                'recommendation': 'Set to nosniff'
            },
            'X-XSS-Protection': {
                'description': 'Enables browser XSS filtering',
                'recommendation': 'Set to 1; mode=block'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information',
                'recommendation': 'Set to strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'description': 'Controls browser features and APIs',
                'recommendation': 'Implement a restrictive permissions policy'
            },
            'Cross-Origin-Opener-Policy': {
                'description': 'Prevents cross-origin window attacks',
                'recommendation': 'Set to same-origin'
            },
            'Cross-Origin-Embedder-Policy': {
                'description': 'Prevents cross-origin resource loading',
                'recommendation': 'Set to require-corp'
            },
            'Cross-Origin-Resource-Policy': {
                'description': 'Controls cross-origin resource loading',
                'recommendation': 'Set to same-site'
            }
        }
        return descriptions.get(header, {'description': 'Unknown header', 'recommendation': 'No recommendation available'})

    def _check_ssl_certificate(self, subdomain):
        """Check SSL certificate information with proper validation."""
        try:
            import ssl
            import socket
            from datetime import datetime

            context = ssl.create_default_context()
            with socket.create_connection((subdomain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=subdomain) as ssock:
                    cert = ssock.getpeercert()
                    
                    expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_remaining = (expires - datetime.now()).days
                    is_expired = days_remaining < 0

                    issuer_org = dict(x[0] for x in cert.get('issuer', [])).get('organizationName', 'Unknown')
                    subject_cn = dict(x[0] for x in cert.get('subject', [])).get('commonName', 'Unknown')

                    return {
                        'valid': not is_expired,
                        'error': 'Certificate is expired' if is_expired else None,
                        'expires': expires.strftime('%Y-%m-%d'),
                        'days_remaining': days_remaining,
                        'is_expired': is_expired,
                        'issuer_org': issuer_org,
                        'subject_cn': subject_cn,
                        'method': 'Python SSL'
                    }

        except ssl.SSLCertVerificationError as e:
            error_reason = f"Validation failed: {e.reason}"
            # Try to get more details if it's a hostname mismatch
            if "hostname mismatch" in str(e).lower():
                try:
                    # Re-fetch the cert without verification to inspect it
                    context_no_verify = ssl._create_unverified_context()
                    with socket.create_connection((subdomain, 443), timeout=5) as sock_no_verify:
                        with context_no_verify.wrap_socket(sock_no_verify, server_hostname=subdomain) as ssock_no_verify:
                            cert = ssock_no_verify.getpeercert()
                            subject_cn = dict(x[0] for x in cert.get('subject', [])).get('commonName', 'Unknown')
                            error_reason = f"Hostname mismatch (cert is for '{subject_cn}')"
                except Exception:
                    pass # Keep the original error reason
            return {'valid': False, 'error': error_reason, 'method': 'Python SSL'}

        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, socket.gaierror, OSError) as e:
            return {'valid': False, 'error': f'Connection error: {type(e).__name__}', 'method': 'Python SSL'}
        
        except Exception as e:
            return {'valid': False, 'error': f'An unexpected SSL error occurred: {str(e)}'}

    def _print_ssl_info(self, ssl_status):
        """Print SSL certificate information, handling all status cases."""
        print(f"{Colors.CYAN}║ {Colors.BOLD}SSL Certificate:{Colors.RESET}{' ' * 58}{Colors.CYAN}║{Colors.RESET}")

        if not isinstance(ssl_status, dict):
            print(f"{Colors.CYAN}║   {Colors.RED}✗ No SSL data available.{' ' * 49}{Colors.CYAN}║{Colors.RESET}")
            return

        is_valid = ssl_status.get('valid', False)
        error = ssl_status.get('error')
        is_expired = ssl_status.get('is_expired', False)
        days_remaining = ssl_status.get('days_remaining')
        expires = ssl_status.get('expires', 'N/A')
        issuer_org = ssl_status.get('issuer_org', 'Unknown')
        subject_cn = ssl_status.get('subject_cn', 'Unknown')

        if is_valid and not error:
            status_text = f"{Colors.GREEN}✓ Valid Certificate"
            if days_remaining is not None:
                if days_remaining <= 7:
                    status_text = f"{Colors.RED}✓ Expires very soon ({days_remaining} days left)"
                elif days_remaining <= 30:
                    status_text = f"{Colors.YELLOW}✓ Expires soon ({days_remaining} days left)"
            print(f"{Colors.CYAN}║   {status_text}{' ' * (68 - len(status_text))}{Colors.CYAN}║{Colors.RESET}")
            print(f"{Colors.CYAN}║   {'Expiry Date:':<15} {expires}{' ' * 45}{Colors.CYAN}║{Colors.RESET}")

        elif error:
            if is_expired:
                status_text = f"{Colors.RED}✗ Expired Certificate"
                print(f"{Colors.CYAN}║   {status_text}{' ' * (68 - len(status_text))}{Colors.CYAN}║{Colors.RESET}")
                print(f"{Colors.CYAN}║   {'Expired On:':<15} {expires}{' ' * 45}{Colors.CYAN}║{Colors.RESET}")
            else:
                status_text = f"{Colors.RED}✗ Invalid Certificate"
                print(f"{Colors.CYAN}║   {status_text}{' ' * (68 - len(status_text))}{Colors.CYAN}║{Colors.RESET}")
                # Truncate long error messages
                error_display = error if len(error) < 50 else error[:47] + "..."
                print(f"{Colors.CYAN}║   {'Reason:':<15} {error_display}{' ' * (50 - len(error_display))}{Colors.CYAN}║{Colors.RESET}")
        
        else: # Not valid, but no specific error given
            print(f"{Colors.CYAN}║   {Colors.RED}✗ Invalid or Incomplete Certificate Data{' ' * 30}{Colors.CYAN}║{Colors.RESET}")
        
        # Always show issuer and subject if available
        if issuer_org != 'Unknown':
             print(f"{Colors.CYAN}║   {'Issuer:':<15} {issuer_org}{' ' * (50 - len(issuer_org))}{Colors.CYAN}║{Colors.RESET}")
        if subject_cn != 'Unknown':
             print(f"{Colors.CYAN}║   {'Subject CN:':<15} {subject_cn}{' ' * (50 - len(subject_cn))}{Colors.CYAN}║{Colors.RESET}")

    def analysis_mode(self, max_subdomains=0):
        """Comprehensive analysis mode with detailed information"""
        print_section_header(f"Starting Comprehensive Analysis for: {self.domain}")
        
        # Initialize variables
        takeover_vulnerable = []
        security_results = {}
        
        # 1. Subdomain discovery
        print_section_header("Phase 1: Subdomain Discovery")
        subdomains = self.scanner.scan()
        
        # Apply max_subdomains limit if specified
        if max_subdomains > 0:
            subdomains = subdomains[:max_subdomains]
            print_info("Limited Analysis", f"Analyzing first {max_subdomains} subdomains", 'warning')
        
        total_subdomains = len(subdomains)
        print_info("Discovered Subdomains", str(total_subdomains), 'success')
        
        # 2. Security analysis
        print_section_header("Phase 2: Security Headers Analysis")
        
        # Analyze main domain
        print_subsection_header(f"Analyzing Main Domain: {self.domain}")
        main_report = self.security_checker.get_headers_report(self.domain)
        if isinstance(main_report, dict):
            security_results[self.domain] = main_report
        else:
            print(f"[DEBUG] Unexpected non-dict main_report for {self.domain}: {main_report}")
        
        # Ensure variables are always defined
        cert_info = {'valid': False}
        headers = {}
        takeover = {}

        if main_report.get('connection_success'):
            print_info("Connection Status", "Connected", 'success')
            print_info("Status Code", str(main_report.get('status_code', 'N/A')))
            print_info("Response Time", f"{main_report.get('response_time', 'N/A')}ms")
            print_info("Server", main_report.get('server', 'Unknown'))

            # SSL Certificate
            print_subsection_header("SSL/TLS Certificate")
            cert_info = self._check_ssl_certificate(self.domain)
            if cert_info['valid']:
                method = cert_info.get('method', 'Unknown')
                
                if method == 'Connection test (fallback)':
                    print_info("Certificate Status", "Valid SSL connection", 'success')
                    print_info("Details", "Certificate details not available", 'warning')
                    print_info("Detection Method", method)
                else:
                    if cert_info['days_remaining'] > 30:
                        print_info("Certificate Status", f"Valid until: {cert_info['expires']} ({cert_info['days_remaining']} days remaining)", 'success')
                    elif cert_info['days_remaining'] > 0:
                        print_info("Certificate Status", f"Expires soon: {cert_info['expires']} ({cert_info['days_remaining']} days remaining)", 'warning')
                    else:
                        print_info("Certificate Status", f"Expired: {cert_info['expires']}", 'error')
                    
                    # Show issuer information
                    if cert_info.get('issuer_org') and cert_info['issuer_org'] != 'Unknown':
                        print_info("Issuer", cert_info['issuer_org'])
                    
                    # Show subject information
                    if cert_info.get('subject_cn') and cert_info['subject_cn'] != 'Unknown':
                        print_info("Subject", cert_info['subject_cn'])
                        
                    # Show method used
                    if cert_info.get('method'):
                        print_info("Detection Method", cert_info['method'])
            else:
                print_info("Certificate Status", "No valid certificate found", 'error')

            # Security Headers
            print_subsection_header("Security Headers")
            headers = main_report.get('headers', {})
            if headers:
                for header, value in headers.items():
                    print_info(header, value, 'success')
            else:
                print_info("Security Headers", "No security headers found", 'warning')

            # Takeover Check
            print_subsection_header("Takeover Vulnerability Check")
            takeover = self._check_takeover(self.domain)
            if takeover.get('vulnerable'):
                service = takeover.get('pattern', 'unknown')
                print_info("Vulnerability Status", f"Takeover vulnerability detected! (Service: {service})", 'error')
                takeover_vulnerable.append(self.domain)
            else:
                print_info("Vulnerability Status", "No takeover vulnerabilities detected", 'success')
        else:
            print_info("Connection Status", "Not Connected", 'error')

        # Security Score
        print_subsection_header("Security Assessment")
        score = self._calculate_security_score(cert_info, headers, takeover)
        
        if score >= 80:
            score_color = Colors.GREEN
            score_emoji = "🟢"
            score_status = 'success'
        elif score >= 60:
            score_color = Colors.YELLOW
            score_emoji = "🟡"
            score_status = 'warning'
        else:
            score_color = Colors.RED
            score_emoji = "🔴"
            score_status = 'error'
        
        print_info(f"Overall Security Score {score_emoji}", f"{score}/100", score_status)
        
        # Analyze subdomains
        print_section_header("Phase 3: Subdomain Analysis")
        print_info("Total Subdomains to Analyze", str(total_subdomains))
        
        for i, subdomain in enumerate(subdomains, 1):
            # Add random delay between 2-5 seconds
            delay = random.uniform(2, 5)
            time.sleep(delay)

            # Use comprehensive security check instead of just headers
            subdomain_report = self._check_security(subdomain)
            if isinstance(subdomain_report, dict):
                security_results[subdomain] = subdomain_report
                # Log the security data
                self._log_security(subdomain_report, 'INFO')
            else:
                print(f"[DEBUG] Unexpected non-dict report for {subdomain}: {subdomain_report}")
            print_subdomain_card(self, subdomain, subdomain_report, i, total_subdomains)
        
        # Analysis Summary
        print_section_header("Analysis Summary")
        
        # Calculate statistics
        total_score = sum(r.get('score', 0) for r in security_results.values())
        avg_score = total_score / len(security_results) if security_results else 0
        high_security = sum(1 for r in security_results.values() if r.get('score', 0) >= 80)
        medium_security = sum(1 for r in security_results.values() if 60 <= r.get('score', 0) < 80)
        low_security = sum(1 for r in security_results.values() if r.get('score', 0) < 60)
        
        print_info("Total Analyzed Subdomains", str(len(security_results)), 'success')
        print_info("Average Security Score", f"{avg_score:.1f}%")
        
        print_subsection_header("Security Score Distribution")
        print_info("High Security (80-100%) 🟢", str(high_security), 'success')
        print_info("Medium Security (60-79%) 🟡", str(medium_security), 'warning')
        print_info("Low Security (<60%) 🔴", str(low_security), 'error')
        
        # Display takeover vulnerabilities
        if takeover_vulnerable:
            print_subsection_header("Detected Takeover Vulnerabilities")
            for subdomain in takeover_vulnerable:
                print_info("Vulnerable Domain", subdomain, 'error')
        
        # Log analysis summary
        self._log_stats({
            'action': 'analysis_summary',
            'total_subdomains': len(subdomains),
            'security_scores': {
                domain: report.get('score', 0)
                for domain, report in security_results.items()
            },
            'connection_status': {
                domain: 'UP' if report.get('connection_success') else 'DOWN'
                for domain, report in security_results.items()
            }
        })

        # --- NEW: Calculate security_stats and performance_stats for the final summary ---
        security_stats = self._calculate_security_stats(security_results)
        performance_stats = self._calculate_performance_stats(security_results)
        self._print_final_summary(security_results)
    
    def security_mode(self):
        """Security-focused analysis mode"""
        print(f"\n{Colors.BOLD}{Colors.PURPLE}🛡️  Security Analysis Mode for: {self.domain}{Colors.RESET}\n")

        # 1. SSL/TLS Certificate Analysis
        print_section_header("Phase 1: SSL/TLS Certificate Analysis")
        ssl_status = self._check_ssl_certificate(self.domain)
        self._print_ssl_info(ssl_status)

        # 2. Security Headers Analysis
        print_section_header("Phase 2: Security Headers Analysis")
        report = self.security_checker.get_headers_report(self.domain)
        headers = report.get('headers', {})
        
        print_subsection_header("Present Security Headers")
        found_headers = [h for h in self.required_headers if h in headers]
        if found_headers:
            for header in found_headers:
                print_info(header, headers[header], 'success')
        else:
            print_info("Status", "No significant security headers found.", 'warning')

        print_subsection_header("Missing Security Headers")
        missing_headers = [h for h in self.required_headers if h not in headers]
        if missing_headers:
            for header in missing_headers:
                print_info(header, "Missing", 'error')
        else:
            print_info("Status", "All critical security headers are present!", 'success')

        # 3. Takeover Vulnerability Check
        print_section_header("Phase 3: Takeover Vulnerability Check")
        takeover_status = self._check_takeover(self.domain)
        if takeover_status.get('vulnerable'):
            print_info("Vulnerability Status", f"Potentially vulnerable! (Reason: {takeover_status.get('reason')})", 'error')
        else:
            print_info("Vulnerability Status", "Seems secure.", 'success')

        # 4. Final Security Score
        print_section_header("Final Security Assessment")
        score = self._calculate_security_score(ssl_status, headers, takeover_status)
        
        score_color = Colors.RED
        if score >= 80: score_color = Colors.GREEN
        elif score >= 50: score_color = Colors.YELLOW
        
        print_info(f"Overall Security Score", f"{score_color}{score}/100{Colors.RESET}")
        
        results = { 'domain': self.domain, 'score': score, 'ssl_status': ssl_status, 'headers': headers, 'takeover': takeover_status }
        self._save_results(results)

    def _print_domain_info(self, domain, report):
        """Print domain information in a structured format"""
        print(f"\n{Colors.CYAN}╔════════════════════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.CYAN}║ {Colors.BOLD}{Colors.WHITE}Domain Analysis: {domain}{Colors.RESET}{' ' * (70 - len(domain))}{Colors.CYAN}║{Colors.RESET}")
        print(f"{Colors.CYAN}╠════════════════════════════════════════════════════════════════════════════╣{Colors.RESET}")
        
        # SSL/TLS Certificate Information
        cert_info = self._check_ssl_certificate(domain)
        print(f"{Colors.CYAN}║ {Colors.BOLD}SSL/TLS Certificate:{Colors.RESET}{' ' * 55}{Colors.CYAN}║{Colors.RESET}")
        if cert_info['valid']:
            method = cert_info.get('method', 'Unknown')
            
            if method == 'Connection test (fallback)':
                print(f"{Colors.CYAN}║   {Colors.GREEN}✓ Valid SSL Connection{Colors.RESET}{' ' * 45}{Colors.CYAN}║{Colors.RESET}")
                print(f"{Colors.CYAN}║   {Colors.YELLOW}Certificate details not available{' ' * 35}{Colors.CYAN}║{Colors.RESET}")
                print(f"{Colors.CYAN}║   {Colors.DIM}Method: {method}{' ' * (55 - len(method))}{Colors.CYAN}║{Colors.RESET}")
            else:
                status_color = Colors.GREEN if cert_info['days_remaining'] > 30 else Colors.YELLOW
                print(f"{Colors.CYAN}║   {status_color}✓ Valid{Colors.RESET} - Expires: {cert_info['expires']} ({cert_info['days_remaining']} days){' ' * (30 - len(str(cert_info['days_remaining'])))}{Colors.CYAN}║{Colors.RESET}")
                
                # Show issuer information
                issuer_org = cert_info.get('issuer_org', 'Unknown')
                if issuer_org != 'Unknown':
                    print(f"{Colors.CYAN}║   Issuer: {issuer_org}{' ' * (65 - len(issuer_org))}{Colors.CYAN}║{Colors.RESET}")
                
                # Show subject information
                subject_cn = cert_info.get('subject_cn', 'Unknown')
                if subject_cn != 'Unknown':
                    print(f"{Colors.CYAN}║   Subject: {subject_cn}{' ' * (65 - len(subject_cn))}{Colors.CYAN}║{Colors.RESET}")
                
                # Show method used
                if method != 'Unknown':
                    print(f"{Colors.CYAN}║   Method: {method}{' ' * (65 - len(method))}{Colors.CYAN}║{Colors.RESET}")
        else:
            print(f"{Colors.CYAN}║   {Colors.RED}✗ Invalid or No Certificate{Colors.RESET}{' ' * 45}{Colors.CYAN}║{Colors.RESET}")
        
        # Security Headers
        print(f"{Colors.CYAN}║ {Colors.BOLD}Security Headers:{Colors.RESET}{' ' * 58}{Colors.CYAN}║{Colors.RESET}")
        headers = report.get('headers', {})
        if headers:
            for header, value in headers.items():
                header_desc = self._get_header_description(header)
                # Use a simple color scheme since importance is not in the description
                importance_color = Colors.GREEN if header in ['Strict-Transport-Security', 'Content-Security-Policy'] else Colors.YELLOW
                print(f"{Colors.CYAN}║   {importance_color}• {header}{Colors.RESET}: {value}{' ' * (60 - len(header) - len(str(value)))}{Colors.CYAN}║{Colors.RESET}")
                print(f"{Colors.CYAN}║     {Colors.DIM}{header_desc['description']}{Colors.RESET}{' ' * (63 - len(header_desc['description']))}{Colors.CYAN}║{Colors.RESET}")
        else:
            print(f"{Colors.CYAN}║   {Colors.RED}No security headers found{Colors.RESET}{' ' * 45}{Colors.CYAN}║{Colors.RESET}")
        
        # Server Information
        print(f"{Colors.CYAN}║ {Colors.BOLD}Server Information:{Colors.RESET}{' ' * 55}{Colors.CYAN}║{Colors.RESET}")
        server = report.get('server', 'Unknown')
        print(f"{Colors.CYAN}║   {Colors.CYAN}Server:{Colors.RESET} {server}{' ' * (65 - len(str(server)))}{Colors.CYAN}║{Colors.RESET}")
        
        # DNS Information
        print(f"{Colors.CYAN}║ {Colors.BOLD}DNS Information:{Colors.RESET}{' ' * 60}{Colors.CYAN}║{Colors.RESET}")
        dns_info = report.get('dns_info', {}) if report else {}
        if dns_info:
            # A Records
            a_records = dns_info.get('a_records', [])
            if a_records:
                a_records_str = ', '.join(str(record) for record in a_records)
                print(f"{Colors.CYAN}║   {Colors.CYAN}A Records:{Colors.RESET} {a_records_str}{' ' * (65 - len(a_records_str))}{Colors.CYAN}║{Colors.RESET}")
            
            # Geo Information
            geo = dns_info.get('geo_info', {})
            if geo:
                location = f"{geo.get('city', '?')}, {geo.get('country', '?')}"
                print(f"{Colors.CYAN}║     Location:{Colors.RESET} {location}{' ' * (60 - len(location))}{Colors.CYAN}║{Colors.RESET}")
                isp = geo.get('isp', '?')
                print(f"{Colors.CYAN}║     ISP:{Colors.RESET} {isp}{' ' * (65 - len(isp))}{Colors.CYAN}║{Colors.RESET}")
        else:
            print(f"{Colors.CYAN}║   {Colors.RED}✗ No DNS information available{Colors.RESET}{' ' * 40}{Colors.CYAN}║{Colors.RESET}")
        
        # Response Time
        print(f"{Colors.CYAN}║ {Colors.BOLD}Response Time:{Colors.RESET}{' ' * 58}{Colors.CYAN}║{Colors.RESET}")
        response_time = report.get('response_time', 0)
        if response_time:
            time_color = Colors.GREEN if response_time < 500 else Colors.YELLOW if response_time < 1000 else Colors.RED
            print(f"{Colors.CYAN}║   {time_color}{response_time}ms{Colors.RESET}{' ' * (65 - len(str(response_time)))}{Colors.CYAN}║{Colors.RESET}")
        else:
            print(f"{Colors.CYAN}║   {Colors.RED}✗ No response time data{Colors.RESET}{' ' * 45}{Colors.CYAN}║{Colors.RESET}")
        
        # Takeover Vulnerability
        print(f"{Colors.CYAN}║ {Colors.BOLD}Takeover Vulnerability:{Colors.RESET}{' ' * 50}{Colors.CYAN}║{Colors.RESET}")
        takeover = self._check_takeover(domain)
        if takeover.get('vulnerable', False):
            service = takeover.get('pattern', 'Unknown')
            print(f"{Colors.CYAN}║   {Colors.RED}⚠ Vulnerable to takeover{Colors.RESET}{' ' * 45}{Colors.CYAN}║{Colors.RESET}")
            print(f"{Colors.CYAN}║   Service: {service}{' ' * (60 - len(service))}{Colors.CYAN}║{Colors.RESET}")
        else:
            print(f"{Colors.CYAN}║   {Colors.GREEN}✓ Protected against takeover{Colors.RESET}{' ' * 40}{Colors.CYAN}║{Colors.RESET}")
        
        # Security Score
        score = self._calculate_security_score(cert_info, headers, takeover)
        score_color = Colors.GREEN if score >= 80 else Colors.YELLOW if score >= 60 else Colors.RED
        print(f"{Colors.CYAN}║ {Colors.BOLD}Security Score:{Colors.RESET}{' ' * 58}{Colors.CYAN}║{Colors.RESET}")
        print(f"{Colors.CYAN}║   {score_color}{score}/100{Colors.RESET}{' ' * 65}{Colors.CYAN}║{Colors.RESET}")
        
        print(f"{Colors.CYAN}╚════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}\n")

    def _print_analysis_summary(self, subdomains, security_stats, performance_stats):
        """Print detailed analysis summary with enhanced statistics"""
        print("\n╔══════════════════════════════════════════════════════════════════════════════╗")
        print("║                          📊 Detailed Analysis Summary                        ║")
        print("╚══════════════════════════════════════════════════════════════════════════════╝\n")

        # Subdomain Statistics
        print("🔍 Subdomain Analysis")
        print("  ┌────────────────────────────────────────────────────────────┐")
        print(f"  │ Total Subdomains Found: {len(subdomains):<40} │")
        active_count = sum(1 for s in subdomains if s.get('status', {}).get('is_accessible', False))
        print(f"  │ Active Subdomains: {active_count:<43} │")
        print(f"  │ Inactive Subdomains: {len(subdomains) - active_count:<41} │")
        
        # Server Distribution
        servers = {}
        for subdomain in subdomains:
            server = subdomain.get('status', {}).get('server', 'Unknown')
            servers[server] = servers.get(server, 0) + 1
        
        print("  ├────────────────────────────────────────────────────────────┤")
        print("  │ Server Distribution:                                        │")
        for server, count in sorted(servers.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  │   • {server}: {count:<45} │")
        print("  └────────────────────────────────────────────────────────────┘\n")

        # Security Statistics
        print("🛡️  Security Analysis")
        print("  ┌────────────────────────────────────────────────────────────┐")
        print(f"  │ Overall Security Score: {security_stats.get('overall_score', 0)}/100{' ' * 35} │")
        
        # SSL Statistics
        ssl_stats = security_stats.get('ssl_stats', {})
        print("  ├────────────────────────────────────────────────────────────┤")
        print("  │ SSL Certificate Status:                                     │")
        print(f"  │   • Valid Certificates: {ssl_stats.get('valid', 0):<40} │")
        print(f"  │   • Expired Certificates: {ssl_stats.get('expired', 0):<38} │")
        print(f"  │   • Missing Certificates: {ssl_stats.get('missing', 0):<38} │")
        
        # Security Headers
        headers_stats = security_stats.get('headers_stats', {})
        print("  ├────────────────────────────────────────────────────────────┤")
        print("  │ Security Headers Implementation:                            │")
        for header, status in headers_stats.items():
            print(f"  │   • {header}: {'✅' if status else '❌'}{' ' * 45} │")
        
        # Takeover Vulnerabilities
        takeover_stats = security_stats.get('takeover_stats', {})
        print("  ├────────────────────────────────────────────────────────────┤")
        print("  │ Takeover Vulnerability Status:                              │")
        print(f"  │   • Vulnerable Subdomains: {takeover_stats.get('vulnerable', 0):<38} │")
        print(f"  │   • Secure Subdomains: {takeover_stats.get('secure', 0):<42} │")
        print("  └────────────────────────────────────────────────────────────┘\n")

        # Performance Statistics
        print("⚡ Performance Analysis")
        print("  ┌────────────────────────────────────────────────────────────┐")
        perf_stats = performance_stats.get('response_times', {})
        print("  │ Response Time Statistics:                                   │")
        print(f"  │   • Average: {perf_stats.get('average', 0):.2f}ms{' ' * 45} │")
        print(f"  │   • Fastest: {perf_stats.get('min', 0):.2f}ms{' ' * 45} │")
        print(f"  │   • Slowest: {perf_stats.get('max', 0):.2f}ms{' ' * 45} │")
        
        # Status Code Distribution
        status_stats = performance_stats.get('status_codes', {})
        print("  ├────────────────────────────────────────────────────────────┤")
        print("  │ Status Code Distribution:                                   │")
        for code, count in sorted(status_stats.items()):
            print(f"  │   • {code}: {count:<45} │")
        
        # Content Types
        content_stats = performance_stats.get('content_types', {})
        print("  ├────────────────────────────────────────────────────────────┤")
        print("  │ Content Type Distribution:                                  │")
        for ctype, count in sorted(content_stats.items(), key=lambda x: x[1], reverse=True)[:5]:
            print(f"  │   • {ctype}: {count:<45} │")
        print("  └────────────────────────────────────────────────────────────┘\n")

        # Recommendations
        print("💡 Security Recommendations")
        print("  ┌────────────────────────────────────────────────────────────┐")
        recommendations = self._generate_recommendations(security_stats)
        for i, rec in enumerate(recommendations, 1):
            print(f"  │ {i}. {rec:<55} │")
        print("  └────────────────────────────────────────────────────────────┘\n")

        # Report Information
        print("📝 Report Information")
        print("  ┌────────────────────────────────────────────────────────────┐")
        print(f"  │ Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{' ' * 20} │")
        print(f"  │ Report Location: reports/analysis_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json{' ' * 5} │")
        print("  └────────────────────────────────────────────────────────────┘\n")

    def _generate_recommendations(self, security_stats):
        """Generate security recommendations based on analysis results"""
        recommendations = []
        
        # SSL Certificate Recommendations
        ssl_stats = security_stats.get('ssl_stats', {})
        if ssl_stats.get('expired', 0) > 0:
            recommendations.append("Renew expired SSL certificates")
        if ssl_stats.get('missing', 0) > 0:
            recommendations.append("Implement SSL certificates for all subdomains")
            
        # Security Headers Recommendations
        headers_stats = security_stats.get('headers_stats', {})
        missing_headers = [h for h, s in headers_stats.items() if not s]
        if missing_headers:
            recommendations.append(f"Implement missing security headers: {', '.join(missing_headers)}")
            
        # Takeover Vulnerability Recommendations
        takeover_stats = security_stats.get('takeover_stats', {})
        if takeover_stats.get('vulnerable', 0) > 0:
            recommendations.append("Address subdomain takeover vulnerabilities")
            
        # General Security Recommendations
        if security_stats.get('overall_score', 0) < 80:
            recommendations.append("Conduct comprehensive security audit")
            
        return recommendations[:5]  # Return top 5 recommendations

    def _print_summary(self, domains, total_score):
        """Print summary of the analysis"""
        print(f"\n{Colors.CYAN}╔════════════════════════════════════════════════════════════════════════════╗{Colors.RESET}")
        print(f"{Colors.CYAN}║ {Colors.BOLD}{Colors.WHITE}Analysis Summary{Colors.RESET}{' ' * 55}{Colors.CYAN}║{Colors.RESET}")
        print(f"{Colors.CYAN}╠════════════════════════════════════════════════════════════════════════════╣{Colors.RESET}")
        print(f"{Colors.CYAN}║ {Colors.BOLD}Total Domains Analyzed:{Colors.RESET} {len(domains)}{' ' * (65 - len(str(len(domains))))}{Colors.CYAN}║{Colors.RESET}")
        print(f"{Colors.CYAN}║ {Colors.BOLD}Average Security Score:{Colors.RESET} {total_score/len(domains):.1f}/100{' ' * 55}{Colors.CYAN}║{Colors.RESET}")
        print(f"{Colors.CYAN}╚════════════════════════════════════════════════════════════════════════════╝{Colors.RESET}\n")
    
    def _save_results(self, results):
        """Save analysis results for both single and multiple reports"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join("reports", f"subspector_report_{self.domain}_{timestamp}.json")
        
        # Determine if we're saving a single report (from security_mode)
        is_single_report = 'score' in results and 'ssl_status' in results

        if is_single_report:
            final_results = {
                'domain': self.domain,
                'report': results,
                'summary': {
                    'analysis_completed': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            }
        else: # Assumes analysis_mode
            final_results = {
                'domain': self.domain,
                'results': results,
                'summary': {
                    'total_analyzed': len(results),
                    'average_security_score': sum(r.get('score', 0) for r in results.values()) / len(results) if results else 0,
                    'analysis_completed': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
            }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(final_results, f, indent=2, ensure_ascii=False, default=str)
            print(f"\n{Colors.GREEN}💾 Analysis results saved: {filename}{Colors.RESET}")
        except Exception as e:
            print(f"\n{Colors.RED}❌ Error saving results: {e}{Colors.RESET}")

    def _export_to_csv(self, domain, results):
        """Export results to CSV format"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join("reports", f"{domain}_report_{timestamp}.csv")
        
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Subdomain', 'Status', 'Response Time', 'Server', 'Security Score', 'Takeover Vulnerable', 'Security Headers'])
            
            for subdomain, data in results.items():
                report = data.get('report', {})
                headers = report.get('headers', {})
                headers_str = ', '.join(headers.keys())
                
                writer.writerow([
                    subdomain,
                    'UP' if report.get('connection_success') else 'DOWN',
                    report.get('response_time', 'N/A'),
                    report.get('server', 'N/A'),
                    data.get('security_score', 0),
                    'Yes' if report.get('takeover_vulnerable') else 'No',
                    headers_str
                ])
        
        return filename

    def _export_to_html(self, domain, results):
        """Export results to HTML format"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join("reports", f"{domain}_report_{timestamp}.html")
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>SubSpector Report - {domain}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .up {{ color: green; }}
                .down {{ color: red; }}
                .vulnerable {{ color: red; }}
                .secure {{ color: green; }}
            </style>
        </head>
        <body>
            <h1>SubSpector Security Report</h1>
            <h2>Domain: {domain}</h2>
            <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            
            <table>
                <tr>
                    <th>Subdomain</th>
                    <th>Status</th>
                    <th>Response Time</th>
                    <th>Server</th>
                    <th>Security Score</th>
                    <th>Takeover Status</th>
                    <th>Security Headers</th>
                </tr>
        """
        
        for subdomain, data in results.items():
            report = data.get('report', {})
            headers = report.get('headers', {})
            headers_str = '<br>'.join(headers.keys())
            
            status_class = 'up' if report.get('connection_success') else 'down'
            takeover_class = 'vulnerable' if report.get('takeover_vulnerable') else 'secure'
            
            html_content += f"""
                <tr>
                    <td>{subdomain}</td>
                    <td class="{status_class}">{'UP' if report.get('connection_success') else 'DOWN'}</td>
                    <td>{report.get('response_time', 'N/A')}</td>
                    <td>{report.get('server', 'N/A')}</td>
                    <td>{data.get('security_score', 0)}</td>
                    <td class="{takeover_class}">{'Vulnerable' if report.get('takeover_vulnerable') else 'Secure'}</td>
                    <td>{headers_str}</td>
                </tr>
            """
        
        html_content += """
            </table>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return filename

    def _log_security_detailed(self, subdomain: str, score: int, missing_headers: List[str], present_headers: List[str], all_headers: Dict[str, str]) -> None:
        """Log security information in JSON format"""
        try:
            log_data = {
                "domain": subdomain,
                "score": score,
                "missing_headers": missing_headers,
                "present_headers": present_headers,
                "all_headers": all_headers,
                "timestamp": datetime.now().isoformat()
            }
            log_with_data(
                security_logger, 
                logging.INFO, 
                f"Security check for {subdomain}", 
                log_data,
                component="security",
                correlation_id=f"scan_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            )
        except Exception as e:
            logger.error(f"Error logging security info: {str(e)}")

    def _log_status(self, subdomain: str, status: str, response_time: float = 0, status_code: int = 0, error: str = None) -> None:
        """Log status information in JSON format"""
        try:
            log_data = {
                "domain": subdomain,
                "status": status,
                "response_time": response_time,
                "status_code": status_code,
                "error": error,
                "timestamp": datetime.now().isoformat()
            }
            log_with_data(
                status_logger, 
                logging.INFO, 
                f"Status check for {subdomain}", 
                log_data,
                component="status",
                correlation_id=f"scan_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            )
        except Exception as e:
            logger.error(f"Error logging status: {str(e)}")

    def _log_terminal(self, message: str, level: str = "info", extra_data: Dict[str, Any] = None) -> None:
        """Log terminal output in JSON format"""
        try:
            log_data = {
                "message": message,
                "level": level,
                **(extra_data or {})
            }
            log_with_data(
                terminal_logger, 
                getattr(logging, level.upper()), 
                message, 
                log_data,
                component="terminal",
                correlation_id=f"scan_{datetime.now().strftime('%Y%m%d%H%M%S')}"
            )
        except Exception as e:
            logger.error(f"Error logging terminal output: {str(e)}")

    def _check_subdomain_status(self, subdomain):
        """Check the status of a subdomain"""
        try:
            # Try to resolve the subdomain
            try:
                socket.gethostbyname(subdomain)
                is_resolvable = True
            except socket.gaierror:
                is_resolvable = False

            # Try to connect to the subdomain
            try:
                response = requests.get(f"https://{subdomain}", 
                                     timeout=5,
                                     verify=False,
                                     allow_redirects=True)
                is_accessible = True
                status_code = response.status_code
                server = response.headers.get('Server', 'Unknown')
            except requests.RequestException:
                is_accessible = False
                status_code = None
                server = None

            # Get DNS records
            try:
                # Set DNS resolver timeout
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                resolver.lifetime = 3
                
                dns_records = {}
                
                # Only check A records for speed (most important)
                try:
                    dns_records['A'] = [str(r) for r in resolver.resolve(subdomain, 'A')]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    dns_records['A'] = []
                
                # Only check CNAME if A records failed (for takeover detection)
                if not dns_records['A']:
                    try:
                        dns_records['CNAME'] = [str(r) for r in resolver.resolve(subdomain, 'CNAME')]
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                        dns_records['CNAME'] = []
                
            except Exception:
                dns_records = {}

            return {
                'is_resolvable': is_resolvable,
                'is_accessible': is_accessible,
                'status_code': status_code,
                'server': server,
                'dns_records': dns_records
            }

        except Exception as e:
            self.logger.error(f"Error checking subdomain status: {str(e)}")
            return {
                'is_resolvable': False,
                'is_accessible': False,
                'status_code': None,
                'server': None,
                'dns_records': {},
                'error': str(e)
            }

    def _check_security(self, subdomain):
        """Check security status of a subdomain"""
        try:
            # Initialize security status
            security_status = {
                'ssl_status': None,
                'headers': None,
                'takeover': None,
                'score': 0
            }

            # Check SSL certificate using the improved method
            security_status['ssl_status'] = self._check_ssl_certificate(subdomain)

            # Check security headers
            try:
                response = requests.get(f"https://{subdomain}", 
                                     timeout=5,  # Reduced from 10 to 5 seconds
                                     verify=False,
                                     allow_redirects=True)
                headers = dict(response.headers)
                security_status['headers'] = headers
            except requests.RequestException as e:
                security_status['headers'] = {'error': str(e)}

            # Check for takeover vulnerability
            try:
                takeover_status = self._check_takeover(subdomain)
                security_status['takeover'] = takeover_status
            except Exception as e:
                security_status['takeover'] = {'error': str(e)}

            # Calculate security score
            security_status['score'] = self._calculate_security_score(
                security_status['ssl_status'],
                security_status['headers'],
                security_status['takeover']
            )

            return security_status

        except Exception as e:
            self.logger.error(f"Error checking security: {str(e)}")
            return {
                'ssl_status': {'error': str(e)},
                'headers': {'error': str(e)},
                'takeover': {'error': str(e)},
                'score': 0
            }

    def _calculate_security_distribution(self, subdomains):
        """Calculate detailed security score distribution"""
        distribution = {
            'excellent': 0,  # 90-100
            'good': 0,       # 70-89
            'fair': 0,       # 50-69
            'poor': 0,       # 30-49
            'critical': 0,   # 0-29
            'details': {
                'ssl_scores': [],
                'headers_scores': [],
                'takeover_scores': []
            }
        }
        
        for subdomain in subdomains:
            security = subdomain.get('security', {})
            score = security.get('score', 0)
            
            # Categorize overall score
            if score >= 90:
                distribution['excellent'] += 1
            elif score >= 70:
                distribution['good'] += 1
            elif score >= 50:
                distribution['fair'] += 1
            elif score >= 30:
                distribution['poor'] += 1
            else:
                distribution['critical'] += 1
            
            # Collect detailed scores
            if 'ssl_status' in security:
                ssl_score = 40 if security['ssl_status'].get('valid', False) else 0
                distribution['details']['ssl_scores'].append(ssl_score)
            
            if 'headers' in security:
                headers_score = sum(10 for header in [
                    'Strict-Transport-Security',
                    'X-Frame-Options',
                    'X-Content-Type-Options',
                    'Content-Security-Policy'
                ] if header in security['headers'])
                distribution['details']['headers_scores'].append(headers_score)
            
            if 'takeover' in security:
                takeover_score = 20 if not security['takeover'].get('vulnerable', False) else 0
                distribution['details']['takeover_scores'].append(takeover_score)
        
        # Calculate averages for detailed scores
        for category in distribution['details']:
            scores = distribution['details'][category]
            if scores:
                distribution['details'][f'{category}_average'] = sum(scores) / len(scores)
            else:
                distribution['details'][f'{category}_average'] = 0
        
        return distribution

    def _print_security_distribution(self, distribution):
        """Print detailed security score distribution"""
        print("\n╔══════════════════════════════════════════════════════════════════════════════╗")
        print("║                        🛡️  Security Score Distribution                        ║")
        print("╚══════════════════════════════════════════════════════════════════════════════╝\n")
        
        print("  ┌────────────────────────────────────────────────────────────┐")
        print("  │ Overall Security Score Distribution:                        │")
        print(f"  │   • Excellent (90-100): {distribution['excellent']:<40} │")
        print(f"  │   • Good (70-89): {distribution['good']:<45} │")
        print(f"  │   • Fair (50-69): {distribution['fair']:<45} │")
        print(f"  │   • Poor (30-49): {distribution['poor']:<45} │")
        print(f"  │   • Critical (0-29): {distribution['critical']:<42} │")
        print("  ├────────────────────────────────────────────────────────────┤")
        
        # Print detailed component scores
        print("  │ Component-wise Security Scores:                             │")
        details = distribution['details']
        print(f"  │   • SSL Certificates: {details.get('ssl_scores_average', 0):.1f}/40{' ' * 40} │")
        print(f"  │   • Security Headers: {details.get('headers_scores_average', 0):.1f}/40{' ' * 40} │")
        print(f"  │   • Takeover Protection: {details.get('takeover_scores_average', 0):.1f}/20{' ' * 40} │")
        
        # Print recommendations based on distribution
        print("  ├────────────────────────────────────────────────────────────┤")
        print("  │ Security Recommendations:                                   │")
        if distribution['critical'] > 0:
            print("  │   • Immediate attention required for critical security issues │")
        if distribution['poor'] > 0:
            print("  │   • Address poor security implementations                  │")
        if details.get('ssl_scores_average', 0) < 30:
            print("  │   • Improve SSL certificate implementation                │")
        if details.get('headers_scores_average', 0) < 30:
            print("  │   • Implement missing security headers                    │")
        if details.get('takeover_scores_average', 0) < 15:
            print("  │   • Strengthen subdomain takeover protection             │")
        print("  └────────────────────────────────────────────────────────────┘\n")

    def _print_final_summary(self, security_results):
        """Print final summary of the analysis"""
        print("\n" + "="*80)
        print(f"{Colors.PURPLE}Final Analysis Summary{Colors.RESET}")
        print("="*80)
        
        # Ensure security_results is a dictionary
        if not isinstance(security_results, dict):
            print(f"{Colors.RED}Error: Invalid security results format{Colors.RESET}")
            return
            
        # Calculate stats with error handling
        try:
            security_stats = self._calculate_security_stats(security_results)
            performance_stats = self._calculate_performance_stats(security_results)
        except Exception as e:
            print(f"{Colors.RED}Error calculating stats: {str(e)}{Colors.RESET}")
            return

        # Overall Statistics
        print(f"\n{Colors.PURPLE}Overall Statistics:{Colors.RESET}")
        total = len(security_results)
        
        # Calculate active/inactive based on SSL status and headers
        active = 0
        inactive = 0
        
        for domain, report in security_results.items():
            if isinstance(report, dict):
                # Consider a subdomain active if:
                # 1. SSL certificate is valid, OR
                # 2. Headers are available (meaning HTTP connection works)
                ssl_status = report.get('ssl_status', {})
                headers = report.get('headers', {})
                
                is_active = False
                
                # Check if SSL is valid
                if ssl_status.get('valid'):
                    is_active = True
                
                # Check if headers are available (HTTP connection works)
                elif headers and 'error' not in headers:
                    is_active = True
                
                # Check if there's any response data
                elif report.get('score', 0) > 0:
                    is_active = True
                
                if is_active:
                    active += 1
                else:
                    inactive += 1
            else:
                inactive += 1
        
        print(f"Total Subdomains: {total}")
        print(f"Active: {active}")
        print(f"Inactive: {inactive}")

        # Security Overview
        print(f"\n{Colors.PURPLE}Security Overview:{Colors.RESET}")
        print(f"Overall Security Score: {security_stats['overall_score']}/100")
        
        # SSL Statistics
        ssl_stats = security_stats['ssl_stats']
        print(f"\nSSL Status:")
        print(f"Valid Certificates: {ssl_stats['valid']}")
        print(f"Expired Certificates: {ssl_stats['expired']}")
        print(f"Missing Certificates: {ssl_stats['missing']}")

        # Headers Statistics
        print(f"\nSecurity Headers:")
        for header, count in security_stats['headers_stats'].items():
            print(f"{header}: {count}/{total}")

        # Takeover Statistics
        takeover_stats = security_stats['takeover_stats']
        print(f"\nSubdomain Takeover:")
        print(f"Vulnerable: {takeover_stats['vulnerable']}")
        print(f"Secure: {takeover_stats['secure']}")

        # Performance Overview
        print(f"\n{Colors.PURPLE}Performance Overview:{Colors.RESET}")
        response_times = performance_stats['response_times']
        print(f"Average Response Time: {response_times['average']:.2f}ms")
        print(f"Min Response Time: {response_times['min']:.2f}ms")
        print(f"Max Response Time: {response_times['max']:.2f}ms")

        # Top Recommendations
        print(f"\n{Colors.PURPLE}Top Recommendations:{Colors.RESET}")
        recommendations = []
        
        # Check SSL issues
        if ssl_stats['expired'] > 0:
            recommendations.append("Renew expired SSL certificates")
        if ssl_stats['missing'] > 0:
            recommendations.append("Implement SSL certificates for all subdomains")
            
        # Check headers
        for header, count in security_stats['headers_stats'].items():
            if count < total:
                recommendations.append(f"Implement {header} on all subdomains")
                
        # Check takeover vulnerabilities
        if takeover_stats['vulnerable'] > 0:
            recommendations.append("Fix subdomain takeover vulnerabilities")
            
        # Print recommendations
        if recommendations:
            for i, rec in enumerate(recommendations[:5], 1):
                print(f"{i}. {rec}")
        else:
            print("No critical issues found")

        # Report Info
        print(f"\n{Colors.PURPLE}Report Information:{Colors.RESET}")
        print(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Target Domain: {self.domain}")
        print(f"Report Location: {self.output_file}")

    def _calculate_security_stats(self, security_results):
        """Calculate security statistics with enhanced error handling"""
        stats = {
            'overall_score': 0,
            'ssl_stats': {'valid': 0, 'expired': 0, 'missing': 0},
            'headers_stats': {},
            'takeover_stats': {'vulnerable': 0, 'secure': 0}
        }
        
        if not isinstance(security_results, dict):
            print(f"{Colors.RED}Error: security_results must be a dictionary{Colors.RESET}")
            return stats
            
        count = 0
        for domain, report in security_results.items():
            if not isinstance(report, dict):
                print(f"{Colors.YELLOW}Warning: Invalid report format for {domain}{Colors.RESET}")
                continue
                
            try:
                # Score calculation
                score = report.get('score', 0)
                if isinstance(score, (int, float)):
                    stats['overall_score'] += score
                    count += 1
                
                # SSL status
                ssl = report.get('ssl_status', {})
                if isinstance(ssl, dict):
                    if ssl.get('valid'):
                        stats['ssl_stats']['valid'] += 1
                    elif ssl.get('error', '').lower().find('expired') != -1:
                        stats['ssl_stats']['expired'] += 1
                    else:
                        stats['ssl_stats']['missing'] += 1
                
                # Takeover status
                takeover = report.get('takeover', {})
                if isinstance(takeover, dict):
                    if takeover.get('vulnerable'):
                        stats['takeover_stats']['vulnerable'] += 1
                    else:
                        stats['takeover_stats']['secure'] += 1
                
                # Headers
                headers = report.get('headers', {})
                if isinstance(headers, dict):
                    for h in ['Strict-Transport-Security', 'X-Frame-Options', 
                             'X-Content-Type-Options', 'Content-Security-Policy']:
                        if h not in stats['headers_stats']:
                            stats['headers_stats'][h] = 0
                        if h in headers:
                            stats['headers_stats'][h] += 1
                            
            except Exception as e:
                print(f"{Colors.YELLOW}Warning: Error processing report for {domain}: {str(e)}{Colors.RESET}")
                continue
        
        if count > 0:
            stats['overall_score'] = int(stats['overall_score'] / count)
            
        return stats

    def _calculate_performance_stats(self, security_results):
        """Calculate performance statistics with enhanced error handling"""
        stats = {'response_times': {'average': 0, 'min': 0, 'max': 0}}
        times = []
        
        if not isinstance(security_results, dict):
            print(f"{Colors.RED}Error: security_results must be a dictionary{Colors.RESET}")
            return stats
            
        for domain, report in security_results.items():
            if not isinstance(report, dict):
                print(f"{Colors.YELLOW}Warning: Invalid report format for {domain}{Colors.RESET}")
                continue
                
            try:
                t = report.get('response_time')
                if t is not None:
                    try:
                        time_value = float(t)
                        if time_value >= 0:  # Ensure non-negative time
                            times.append(time_value)
                    except (ValueError, TypeError):
                        print(f"{Colors.YELLOW}Warning: Invalid response time for {domain}: {t}{Colors.RESET}")
            except Exception as e:
                print(f"{Colors.YELLOW}Warning: Error processing response time for {domain}: {str(e)}{Colors.RESET}")
                continue
        
        if times:
            stats['response_times']['average'] = sum(times) / len(times)
            stats['response_times']['min'] = min(times)
            stats['response_times']['max'] = max(times)
            
        return stats

    def _cleanup_old_logs(self):
        """Clean up old logs to manage file sizes"""
        for log_file in self.log_files.values():
            if os.path.exists(log_file):
                log_size = os.path.getsize(log_file)
                if log_size > self.max_log_size:
                    with open(log_file, 'r', encoding='utf-8') as f:
                        log_data = json.load(f)
                    
                    # Keep only the last 1000 entries
                    log_data['entries'] = log_data['entries'][-1000:]
                    
                    with open(log_file, 'w', encoding='utf-8') as f:
                        json.dump(log_data, f, indent=2, ensure_ascii=False, default=str)
    
    def _cleanup_empty_logs(self):
        """Remove empty log files"""
        try:
            for log_file in self.log_files.values():
                if os.path.exists(log_file):
                    try:
                        with open(log_file, 'r', encoding='utf-8') as f:
                            content = f.read().strip()
                        if not content or content == '{"entries": []}':
                            try:
                                os.remove(log_file)
                            except OSError:
                                pass  # Suppress file access error messages
                    except (OSError, IOError):
                        pass  # Suppress file access error messages
        except Exception:
            pass  # Suppress all cleanup errors
    
    def _compress_old_logs(self):
        """Compress old log files to save space"""
        import gzip
        import glob
        from datetime import datetime, timedelta
        
        # Find log files older than 7 days
        cutoff_date = datetime.now() - timedelta(days=7)
        
        for log_pattern in ['logs/**/*.json']:
            for log_file in glob.glob(log_pattern, recursive=True):
                try:
                    file_time = datetime.fromtimestamp(os.path.getmtime(log_file))
                    if file_time < cutoff_date:
                        # Compress the file
                        with open(log_file, 'rb') as f_in:
                            with gzip.open(f"{log_file}.gz", 'wb') as f_out:
                                f_out.writelines(f_in)
                        
                        # Remove original file
                        os.remove(log_file)
                        print(f"Compressed old log file: {log_file}")
                except Exception as e:
                    print(f"Error compressing log file {log_file}: {e}")
    
    def _manage_log_size(self, log_file_path):
        """Manage log file size to prevent excessive growth"""
        if os.path.exists(log_file_path):
            try:
                with open(log_file_path, 'r', encoding='utf-8') as f:
                    log_data = json.load(f)
                
                # If file has too many entries, keep only the latest ones
                if 'entries' in log_data and len(log_data['entries']) > self.max_entries:
                    log_data['entries'] = log_data['entries'][-self.max_entries:]
                    
                    with open(log_file_path, 'w', encoding='utf-8') as f:
                        json.dump(log_data, f, indent=2, ensure_ascii=False, default=str)
                        
            except Exception as e:
                print(f"Error managing log size for {log_file_path}: {e}")
    
    def _manage_terminal_log(self):
        """Special management for terminal logs to prevent excessive size"""
        terminal_log = self.log_files['terminal']
        if os.path.exists(terminal_log):
            try:
                file_size = os.path.getsize(terminal_log)
                if file_size > 5 * 1024 * 1024:  # 5MB limit for terminal logs
                    # Keep only the last 500 entries for terminal logs
                    with open(terminal_log, 'r', encoding='utf-8') as f:
                        log_data = json.load(f)
                    
                    if 'entries' in log_data and len(log_data['entries']) > 500:
                        log_data['entries'] = log_data['entries'][-500:]
                        
                        with open(terminal_log, 'w', encoding='utf-8') as f:
                            json.dump(log_data, f, indent=2, ensure_ascii=False, default=str)
                        
                        print(f"Terminal log size reduced to {len(log_data['entries'])} entries")
                        
            except Exception as e:
                print(f"Error managing terminal log: {e}")
    
    def _log_with_size_management(self, log_file_path, data):
        """Log data with automatic size management"""
        try:
            # Log the data
            with open(log_file_path, 'r', encoding='utf-8') as f:
                log_data = json.load(f)
            
            log_data['entries'].append(data)
            
            # Manage size if needed
            if len(log_data['entries']) > self.max_entries:
                log_data['entries'] = log_data['entries'][-self.max_entries:]
            
            with open(log_file_path, 'w', encoding='utf-8') as f:
                json.dump(log_data, f, indent=2, ensure_ascii=False, default=str)
                
        except Exception as e:
            print(f"Error in _log_with_size_management: {e}")

    def _check_openssl_availability(self):
        """Check if OpenSSL is available for better SSL certificate details"""
        try:
            # Check if openssl command is available
            result = subprocess.run(['openssl', '-version'], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout:
                return True
            else:
                return False
        except Exception:
            return False  # Suppress error messages

def truncate_value(value, max_length=80):
    if not isinstance(value, str):
        value = str(value)
    return value if len(value) <= max_length else value[:max_length] + '... [truncated]'

def print_subdomain_card(subspector, subdomain, report, index, total):
    """Print detailed subdomain information in a visually organized card format"""
    LINE = f"{Colors.PURPLE}{'═'*78}{Colors.RESET}"
    SUBLINE = f"{Colors.PURPLE}{'─'*78}{Colors.RESET}"
    MARGIN = '  '
    if not report:
        print(f"\n{LINE}")
        print(f"{Colors.PURPLE}{MARGIN}🟣 Subdomain {index}/{total}: {subdomain}{Colors.RESET}")
        print(f"{SUBLINE}")
        print(f"{Colors.RED}{MARGIN}✗ No data available for this subdomain{Colors.RESET}")
        print(f"{LINE}")
        return

    # Card Header
    print(f"\n{LINE}")
    print(f"{Colors.PURPLE}{MARGIN}🟣 Subdomain {index}/{total}: {subdomain}{Colors.RESET}")
    print(f"{SUBLINE}")

    # 1. Connection Status Section
    print(f"{Colors.PURPLE}{MARGIN}🔌 Connection Status{Colors.RESET}")
    # Check if we can connect based on SSL status and headers
    ssl_status = report.get('ssl_status', {})
    headers = report.get('headers', {})
    
    if ssl_status.get('valid') or (headers and 'error' not in headers):
        print(f"{Colors.GREEN}{MARGIN}  ✓ Connected{Colors.RESET}")
    else:
        print(f"{Colors.RED}{MARGIN}  ✗ Connection Failed{Colors.RESET}")
        if 'error' in ssl_status:
            print(f"{Colors.RED}{MARGIN}    SSL Error: {ssl_status['error']}{Colors.RESET}")
    print(f"{SUBLINE}")

    # 2. Server & DNS Information Section
    print(f"{Colors.PURPLE}{MARGIN}🌐 Server & DNS Information{Colors.RESET}")
    # Try to get server info from headers
    server = 'Unknown'
    if headers and 'error' not in headers:
        server = headers.get('Server', headers.get('server', 'Unknown'))
    print(f"{Colors.CYAN}{MARGIN}  Server:{Colors.RESET} {server}")
    # Get and print A records
    a_records = get_a_records(subdomain)
    if a_records:
        print(f"{Colors.CYAN}{MARGIN}  A Records:{Colors.RESET} {', '.join(a_records)}")
    else:
        print(f"{Colors.CYAN}{MARGIN}  A Records:{Colors.RESET} N/A")
    print(f"{SUBLINE}")

    # 3. Security Score Section
    score = report.get('score', 0)
    if score >= 80:
        score_color = Colors.GREEN
        score_emoji = "🟢"
        score_status = "Excellent"
    elif score >= 60:
        score_color = Colors.YELLOW
        score_emoji = "🟡"
        score_status = "Good"
    else:
        score_color = Colors.RED
        score_emoji = "🔴"
        score_status = "Needs Improvement"
    print(f"{Colors.PURPLE}{MARGIN}🔒 Security Score:{Colors.RESET} {score_color}{score_emoji} {score}% - {score_status}{Colors.RESET}")
    print(f"{SUBLINE}")

    # 4. SSL Certificate Section
    print(f"{Colors.PURPLE}{MARGIN}🔐 SSL Certificate{Colors.RESET}")
    if ssl_status.get('valid'):
        # Show method used for detection first
        method = ssl_status.get('method', 'Unknown')
        if method == 'Connection test':
            print(f"{Colors.GREEN}{MARGIN}  ✓ Valid SSL Certificate{Colors.RESET}")
            print(f"{Colors.YELLOW}{MARGIN}    SSL connection successful, but certificate details not available{Colors.RESET}")
            print(f"{Colors.DIM}{MARGIN}    Method: {method}{Colors.RESET}")
        else:
            # Show detailed certificate information
            if 'days_remaining' in ssl_status and ssl_status['days_remaining'] > 0:
                days = ssl_status['days_remaining']
                if days > 30:
                    days_color = Colors.GREEN
                    status_text = "Valid"
                    print(f"{days_color}{MARGIN}  ✓ {status_text} SSL Certificate ({days} days remaining){Colors.RESET}")
                elif days > 7:
                    days_color = Colors.YELLOW
                    status_text = "Expires Soon"
                    print(f"{days_color}{MARGIN}  ✓ {status_text} SSL Certificate ({days} days remaining){Colors.RESET}")
                else:
                    days_color = Colors.RED
                    status_text = "Expires Very Soon"
                    print(f"{days_color}{MARGIN}  ✓ {status_text} SSL Certificate ({days} days remaining){Colors.RESET}")
            else:
                print(f"{Colors.GREEN}{MARGIN}  ✓ Valid SSL Certificate{Colors.RESET}")
            
            # Show expiry date (always show if available)
            if 'expires' in ssl_status and ssl_status['expires'] != 'Unknown':
                print(f"{Colors.CYAN}{MARGIN}  Expiry Date:{Colors.RESET} {ssl_status['expires']}")
            elif 'expires' in ssl_status and ssl_status['expires'] == 'Unknown':
                print(f"{Colors.YELLOW}{MARGIN}  Expiry Date:{Colors.RESET} Unknown")
            
            # Show issuer information
            if 'issuer_org' in ssl_status and ssl_status['issuer_org'] not in ['Unknown', 'Connection Test']:
                print(f"{Colors.CYAN}{MARGIN}  Issuer:{Colors.RESET} {ssl_status['issuer_org']}")
            
            # Show subject information
            if 'subject_cn' in ssl_status and ssl_status['subject_cn'] not in ['Unknown', subdomain]:
                print(f"{Colors.CYAN}{MARGIN}  Subject:{Colors.RESET} {ssl_status['subject_cn']}")
            
            # Show method used for detection
            if 'method' in ssl_status:
                print(f"{Colors.DIM}{MARGIN}  Method:{Colors.RESET} {ssl_status['method']}")
            
    else:
        error_msg = ssl_status.get('error', 'No valid SSL certificate')
        print(f"{Colors.RED}{MARGIN}  ✗ {error_msg}{Colors.RESET}")
        
        # Show more specific error information
        if 'SSL Error:' in error_msg:
            print(f"{Colors.YELLOW}{MARGIN}    (SSL/TLS configuration issue){Colors.RESET}")
        elif 'Connection timeout' in error_msg:
            print(f"{Colors.YELLOW}{MARGIN}    (Server not responding){Colors.RESET}")
        elif 'DNS resolution failed' in error_msg:
            print(f"{Colors.YELLOW}{MARGIN}    (Domain not found){Colors.RESET}")
        elif 'Connection refused' in error_msg:
            print(f"{Colors.YELLOW}{MARGIN}    (Port 443 not open){Colors.RESET}")
    
    print(f"{SUBLINE}")

    # 5. Security Headers Section
    print(f"{Colors.PURPLE}{MARGIN}🛡️  Security Headers{Colors.RESET}")
    if headers and 'error' not in headers:
        critical_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy'
        ]
        found_headers = []
        for header in critical_headers:
            if header in headers:
                found_headers.append(header)
                print(f"{Colors.GREEN}{MARGIN}  ✓ {header}{Colors.RESET}")
        
        if not found_headers:
            print(f"{Colors.RED}{MARGIN}  ✗ No critical security headers found{Colors.RESET}")
    else:
        print(f"{Colors.RED}{MARGIN}  ✗ No headers data available{Colors.RESET}")
    print(f"{SUBLINE}")

    # 6. Takeover Vulnerability Section
    print(f"{Colors.PURPLE}{MARGIN}⚠️  Takeover Vulnerability{Colors.RESET}")
    takeover = report.get('takeover', {})
    if takeover.get('vulnerable'):
        service = takeover.get('service', 'unknown')
        print(f"{Colors.RED}{MARGIN}  ⚠️  Potentially vulnerable to takeover ({service}){Colors.RESET}")
    else:
        print(f"{Colors.GREEN}{MARGIN}  ✓ Secure against subdomain takeover{Colors.RESET}")
    print(f"{LINE}")

def get_a_records(domain):
    """Get A records for a domain with improved error handling"""
    try:
        # Set up resolver with shorter timeout
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        # Try with default DNS first
        try:
            answers = resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except (dns.resolver.Timeout, dns.exception.Timeout):
            # If timeout, try with public DNS servers
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']
            resolver.timeout = 1.5
            resolver.lifetime = 1.5
            answers = resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
            
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except (dns.resolver.Timeout, dns.exception.Timeout):
        return []
    except Exception:
        return []

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='SubSpector - Advanced Subdomain Monitoring & Security Analysis Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subspector.py example.com                    # Quick security analysis
  python subspector.py example.com -m monitor         # Continuous monitoring
  python subspector.py example.com -m analysis        # Comprehensive analysis
  python subspector.py example.com -m security        # Security-focused scan
  python subspector.py example.com -i 600             # Monitor with 10min interval
        """
    )
    
    parser.add_argument('domain', help='Target domain to analyze')
    parser.add_argument('-m', '--mode', 
                       choices=['monitor', 'analysis', 'security'], 
                       default='security',
                       help='Analysis mode (default: security)')
    parser.add_argument('-i', '--interval', 
                       type=int, 
                       default=300,
                       help='Monitoring interval in seconds (default: 300)')
    parser.add_argument('-n', '--max-subdomains', 
                       type=int, 
                       default=0,
                       help='Maximum subdomains to analyze (default: 0 - no limit)')
    parser.add_argument('--no-banner', 
                       action='store_true',
                       help='Skip banner display')
    
    args = parser.parse_args()
    
    # Display banner
    if not args.no_banner:
        print_banner()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Initialize SubSpector
    subspector = SubSpector(args.domain, args.mode)
    
    try:
        if args.mode == 'monitor':
            subspector.monitor_mode(args.interval)
        elif args.mode == 'analysis':
            subspector.analysis_mode(args.max_subdomains)
        elif args.mode == 'security':
            subspector.security_mode()
    
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⏹️  SubSpector stopped by user{Colors.RESET}")
    except Exception as e:
        print(f"\n{Colors.RED}❌ Error: {str(e)}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main() 