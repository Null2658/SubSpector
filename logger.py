# logger.py
import logging
import logging.handlers
import json
import os
from datetime import datetime, timedelta
from config import Config
from typing import Dict, Any, List, Optional
from pathlib import Path
import gzip
import shutil

def setup_logger():
    """
    Setup main logger with all handlers
    """
    # Create logger
    logger = logging.getLogger('subspector')
    logger.setLevel(logging.DEBUG)
    
    # Create logs directory and subdirectories
    subdirs = ["headers", "security", "status", "stats", "updown", "whois", "terminal"]
    for subdir in subdirs:
        os.makedirs(os.path.join('logs', subdir), exist_ok=True)
    
    # Setup console logging
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # Setup terminal-like logging
    terminal_handler = logging.FileHandler(
        os.path.join('logs', 'terminal', 'terminal.log'),
        encoding='utf-8'
    )
    terminal_handler.setLevel(logging.INFO)
    terminal_formatter = logging.Formatter(
        "%(message)s"  # No timestamp for terminal-like output
    )
    terminal_handler.setFormatter(terminal_formatter)
    logger.addHandler(terminal_handler)

    # Setup security logging
    security_handler = setup_security_logger()
    logger.addHandler(security_handler)
    
    # Setup headers logging
    headers_handler = setup_headers_logger()
    logger.addHandler(headers_handler)
    
    # Setup updown logging
    up_handler, down_handler = setup_updown_loggers()
    logger.addHandler(up_handler)
    logger.addHandler(down_handler)
    
    # Setup stats logging
    stats_handler = setup_stats_logger()
    logger.addHandler(stats_handler)
    
    # Setup WHOIS logging
    whois_handler = setup_whois_logger()
    logger.addHandler(whois_handler)
    
    return logger

class JSONFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # Base log data
        log_data = {
            "timestamp": datetime.fromtimestamp(record.created).strftime("%Y-%m-%d %H:%M:%S"),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add extra fields if they exist
        if hasattr(record, 'extra_data'):
            # Convert any datetime objects in extra_data to strings
            extra_data = record.extra_data.copy()
            for key, value in extra_data.items():
                if isinstance(value, datetime):
                    extra_data[key] = value.strftime("%Y-%m-%d %H:%M:%S")
            log_data.update(extra_data)
            
        # Add component-specific data
        if hasattr(record, 'component'):
            log_data['component'] = record.component
            
        # Add correlation ID for tracking related logs
        if hasattr(record, 'correlation_id'):
            log_data['correlation_id'] = record.correlation_id
            
        return json.dumps(log_data, ensure_ascii=False, indent=2)

def setup_security_logger():
    """
    Setup security logging
    """
    security_handler = logging.handlers.RotatingFileHandler(
        os.path.join('logs', 'security', 'security.log'),
        maxBytes=Config.LOG_CONFIG['max_size'],
        backupCount=Config.LOG_CONFIG['backup_count'],
        encoding='utf-8'
    )
    security_handler.setLevel(logging.WARNING)
    security_formatter = JSONFormatter()
    security_handler.setFormatter(security_formatter)
    return security_handler

def setup_headers_logger():
    """
    Setup headers logging
    """
    headers_handler = logging.handlers.RotatingFileHandler(
        os.path.join('logs', 'headers', 'headers.log'),
        maxBytes=Config.LOG_CONFIG['max_size'],
        backupCount=Config.LOG_CONFIG['backup_count'],
        encoding='utf-8'
    )
    headers_handler.setLevel(logging.INFO)
    headers_formatter = JSONFormatter()
    headers_handler.setFormatter(headers_formatter)
    return headers_handler

def setup_updown_loggers():
    """
    Setup UP/DOWN logging
    """
    up_handler = logging.handlers.RotatingFileHandler(
        os.path.join('logs', 'updown', 'up.log'),
        maxBytes=Config.LOG_CONFIG['max_size'],
        backupCount=Config.LOG_CONFIG['backup_count'],
        encoding='utf-8'
    )
    up_handler.setLevel(logging.INFO)
    up_formatter = JSONFormatter()
    up_handler.setFormatter(up_formatter)
    
    down_handler = logging.handlers.RotatingFileHandler(
        os.path.join('logs', 'updown', 'down.log'),
        maxBytes=Config.LOG_CONFIG['max_size'],
        backupCount=Config.LOG_CONFIG['backup_count'],
        encoding='utf-8'
    )
    down_handler.setLevel(logging.WARNING)
    down_formatter = JSONFormatter()
    down_handler.setFormatter(down_formatter)
    
    return up_handler, down_handler

def setup_stats_logger():
    """
    Setup statistics logging
    """
    stats_handler = logging.handlers.RotatingFileHandler(
        os.path.join('logs', 'stats', 'stats.log'),
        maxBytes=Config.LOG_CONFIG['max_size'],
        backupCount=Config.LOG_CONFIG['backup_count'],
        encoding='utf-8'
    )
    stats_handler.setLevel(logging.INFO)
    stats_formatter = JSONFormatter()
    stats_handler.setFormatter(stats_formatter)
    return stats_handler

def setup_whois_logger():
    """
    Setup WHOIS logging
    """
    whois_handler = logging.handlers.RotatingFileHandler(
        os.path.join('logs', 'whois', 'whois.log'),
        maxBytes=Config.LOG_CONFIG['max_size'],
        backupCount=Config.LOG_CONFIG['backup_count'],
        encoding='utf-8'
    )
    whois_handler.setLevel(logging.INFO)
    whois_formatter = JSONFormatter()
    whois_handler.setFormatter(whois_formatter)
    return whois_handler

def log_headers(logger, subdomain, headers, security_score=0, missing_headers=None, present_headers=None):
    """
    Log HTTP headers information with security details
    """
    if missing_headers is None:
        missing_headers = []
    if present_headers is None:
        present_headers = []
        
    try:
        logger.info(
            f"Security headers check for {subdomain}",
            extra={
                'domain': subdomain,
                'score': security_score,
                'missing_headers': '\n'.join(f"- {h}" for h in missing_headers) if missing_headers else "None",
                'present_headers': '\n'.join(f"- {h}" for h in present_headers) if present_headers else "None",
                'all_headers': '\n'.join(f"{k}: {v}" for k, v in headers.items()) if headers else "None"
            }
        )
    except Exception as e:
        logger.error(f"Error logging headers for {subdomain}: {str(e)}")

def log_security_event(logger, event_type, target, details, risk_level="Medium", recommended_action="Monitor", security_score=0):
    """
    Log security events with proper domain information and risk assessment
    """
    extra = {
        'domain': target,
        'details': details,
        'risk_level': risk_level,
        'action': recommended_action,
        'score': security_score,
        'missing_headers': '',
        'present_headers': '',
        'all_headers': ''
    }
    
    if event_type == "ssl_error":
        logger.warning(f"SSL check failed for {target}: {details}", extra=extra)
    elif event_type == "header_missing":
        logger.warning(f"Missing security headers for {target}: {details}", extra=extra)
    elif event_type == "takeover_risk":
        logger.error(f"Potential takeover vulnerability detected for {target}: {details}", extra=extra)
    else:
        logger.warning(f"Security issue detected for {target}: {details}", extra=extra)

def log_status_change(logger, subdomain, old_status, new_status, status_code=None, additional_info=None):
    """
    Log subdomain status changes
    """
    try:
        status_data = {
            'timestamp': datetime.now().isoformat(),
            'subdomain': subdomain,
            'old_status': old_status,
            'new_status': new_status,
            'status_code': status_code,
            'additional_info': additional_info or {}
        }
        
        if new_status == 'UP':
            logger.info(
                f"Subdomain {subdomain} is now UP",
                extra=status_data
            )
        else:
            logger.warning(
                f"Subdomain {subdomain} is now DOWN",
                extra=status_data
            )
            
    except Exception as e:
        logger.error(f"Error logging status change: {str(e)}")

def log_daily_summary(logger, total_subdomains, up_count, down_count, changes):
    """
    Log daily summary of monitoring
    """
    logger.info(
        "Daily monitoring summary",
        extra={
            'total': total_subdomains,
            'active': up_count,
            'inactive': down_count,
            'changes': changes
        }
    )

def log_scan_statistics(logger, stats_data):
    """
    Log scan statistics
    """
    try:
        logger.info(
            "Scan statistics",
            extra={'stats': stats_data}
        )
    except Exception as e:
        logger.error(f"Error logging scan statistics: {str(e)}")

def log_subdomain_changes(logger, changes: dict, timestamp: str = None):
    """
    Log changes in subdomains
    """
    if timestamp is None:
        timestamp = datetime.now().isoformat()
        
    try:
        logger.info(
            "Subdomain changes detected",
            extra={
                'timestamp': timestamp,
                'changes': changes
            }
        )
    except Exception as e:
        logger.error(f"Error logging subdomain changes: {str(e)}")

class LogManager:
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        self.compress_after_days = 7  # Compress logs older than 7 days
        self.max_log_size = 10 * 1024 * 1024  # 10MB
        
    def setup_logger(self, name: str, log_file: str, level: int = logging.INFO) -> logging.Logger:
        """Setup a logger with JSON formatting and rotation"""
        # Create component directory
        component_dir = self.log_dir / name
        component_dir.mkdir(exist_ok=True)
        
        # Create log file with timestamp
        timestamp = datetime.now().strftime("%Y%m%d")
        log_path = component_dir / f"{name}_{timestamp}.json"
        
        # Create logger
        logger = logging.getLogger(name)
        logger.setLevel(level)
        
        # Create file handler with rotation
        file_handler = logging.FileHandler(log_path, encoding='utf-8')
        file_handler.setLevel(level)
        
        # Create JSON formatter
        json_formatter = JSONFormatter()
        file_handler.setFormatter(json_formatter)
        
        # Add handler to logger
        logger.addHandler(file_handler)
        
        # Compress old logs
        self._compress_old_logs(component_dir)
        
        return logger
    
    def _compress_old_logs(self, log_dir: Path) -> None:
        """Compress log files older than compress_after_days"""
        cutoff_date = datetime.now() - timedelta(days=self.compress_after_days)
        
        for log_file in log_dir.glob("*.json"):
            if not log_file.name.endswith(".gz"):
                try:
                    file_date = datetime.strptime(log_file.stem.split("_")[-1], "%Y%m%d")
                    if file_date < cutoff_date:
                        # Compress the file
                        with open(log_file, 'rb') as f_in:
                            with gzip.open(f"{log_file}.gz", 'wb') as f_out:
                                shutil.copyfileobj(f_in, f_out)
                        # Remove original file
                        log_file.unlink()
                except (ValueError, IndexError):
                    continue
    
    def search_logs(self, 
                   component: str, 
                   start_date: Optional[datetime] = None,
                   end_date: Optional[datetime] = None,
                   level: Optional[str] = None,
                   search_term: Optional[str] = None) -> List[Dict[str, Any]]:
        """Search through logs with various filters"""
        results = []
        component_dir = self.log_dir / component
        
        if not component_dir.exists():
            return results
            
        # Get all log files (including compressed ones)
        log_files = list(component_dir.glob("*.json")) + list(component_dir.glob("*.json.gz"))
        
        for log_file in log_files:
            try:
                # Check if file is compressed
                if log_file.suffix == '.gz':
                    with gzip.open(log_file, 'rt', encoding='utf-8') as f:
                        logs = [json.loads(line) for line in f]
                else:
                    with open(log_file, 'r', encoding='utf-8') as f:
                        logs = [json.loads(line) for line in f]
                
                # Apply filters
                for log in logs:
                    log_date = datetime.fromisoformat(log['timestamp'])
                    
                    # Date filter
                    if start_date and log_date < start_date:
                        continue
                    if end_date and log_date > end_date:
                        continue
                        
                    # Level filter
                    if level and log['level'] != level:
                        continue
                        
                    # Search term filter
                    if search_term:
                        if not any(search_term.lower() in str(v).lower() 
                                 for v in log.values()):
                            continue
                            
                    results.append(log)
                    
            except Exception as e:
                print(f"Error reading log file {log_file}: {str(e)}")
                continue
                
        return results

def log_with_data(logger: logging.Logger, 
                 level: int, 
                 message: str, 
                 extra_data: Dict[str, Any] = None,
                 component: str = None,
                 correlation_id: str = None) -> None:
    """Log a message with extra data and metadata"""
    if extra_data is None:
        extra_data = {}
        
    extra = {
        'extra_data': extra_data,
        'component': component,
        'correlation_id': correlation_id
    }
    
    logger.log(level, message, extra=extra)

# Create log manager instance
log_manager = LogManager()

# Create loggers for different components
headers_logger = log_manager.setup_logger("headers", "headers")
security_logger = log_manager.setup_logger("security", "security")
status_logger = log_manager.setup_logger("status", "status")
stats_logger = log_manager.setup_logger("stats", "stats")
updown_logger = log_manager.setup_logger("updown", "updown")
whois_logger = log_manager.setup_logger("whois", "whois")
terminal_logger = log_manager.setup_logger("terminal", "terminal")

# Example usage:
# log_with_data(security_logger, logging.INFO, "Security check completed", {
#     "domain": "example.com",
#     "score": 85,
#     "vulnerabilities": ["XSS", "CSRF"]
# }, component="security", correlation_id="scan_123")
