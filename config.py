# config.py
import os
from typing import Dict, List

class Config:
    """
    Configuration settings for SubSpector
    """
    # Domain to monitor - will be set from command line
    DOMAIN = None
    
    # Scan settings
    SCAN_INTERVAL = 300  # 5 minutes
    MAX_SUBDOMAINS = 1000
    TIMEOUT = 10  # seconds
    
    # Security settings
    SECURITY_HEADERS = {
        "Strict-Transport-Security": {"weight": 20, "risk_level": "Critical"},
        "Content-Security-Policy": {"weight": 20, "risk_level": "Critical"},
        "X-Frame-Options": {"weight": 15, "risk_level": "High"},
        "X-Content-Type-Options": {"weight": 10, "risk_level": "High"},
        "X-XSS-Protection": {"weight": 10, "risk_level": "Medium"},
        "Referrer-Policy": {"weight": 10, "risk_level": "Medium"},
        "Permissions-Policy": {"weight": 10, "risk_level": "Medium"},
        "Cross-Origin-Opener-Policy": {"weight": 15, "risk_level": "High"},
        "Cross-Origin-Embedder-Policy": {"weight": 15, "risk_level": "High"},
        "Cross-Origin-Resource-Policy": {"weight": 10, "risk_level": "Medium"}
    }
    
    # Logging configuration
    LOG_CONFIG = {
        "max_size": 10485760,  # 10MB
        "backup_count": 5
    }
    
    # WHOIS settings
    WHOIS_CHECK_INTERVAL = 86400  # 24 hours
    WHOIS_EXPIRY_WARNING = 30  # days
    WHOIS_EXPIRY_CRITICAL = 7  # days
    WHOIS_CACHE_DURATION = 86400  # 24 hours
    
    # Time intervals (in seconds)
    RUN_INTERVAL = 300   # 5 minutes
    DELAY_BETWEEN_CHECKS = 2  # 2 seconds between checks
    RETRY_ATTEMPTS = 3  # Number of retry attempts
    
    # File names for storing data
    OLD_SUBDOMAINS_FILE = "old_subdomains.json"
    
    # Security settings
    SECURITY_SCORE_THRESHOLD = 80  # Minimum acceptable security score
    
    # Notification settings
    NOTIFY_TELEGRAM = True
    NOTIFY_SLACK = True
    NOTIFY_EMAIL = True
    NOTIFY_ON_STARTUP = True
    NOTIFY_ON_SHUTDOWN = True
    NOTIFY_ON_ERROR = True
    NOTIFY_ON_STATUS_CHANGE = True
    NOTIFY_ON_NEW_SUBDOMAIN = True
    NOTIFY_ON_REMOVED_SUBDOMAIN = True
    NOTIFY_ON_SECURITY_ISSUE = True
    NOTIFY_ON_WHOIS_WARNING = True
    NOTIFY_ON_WHOIS_CRITICAL = True
    
    # Notifications configuration
    NOTIFICATIONS = {
        "telegram": {
            "enabled": False,
            "bot_token": "",
            "chat_id": ""
        },
        "slack": {
            "enabled": False,
            "webhook_url": ""
        },
        "email": {
            "enabled": False,
            "smtp_server": "",
            "smtp_port": 587,
            "username": "",
            "password": "",
            "from": "",
            "to": ""
        }
    }
    
    @staticmethod
    def get_notification_config() -> Dict:
        """Get notification settings"""
        return Config.NOTIFICATIONS
