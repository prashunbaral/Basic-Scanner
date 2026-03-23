"""
Logging system for the vulnerability discovery framework
"""
import logging
import sys
from pathlib import Path
from datetime import datetime
from scanner.config import LOG_LEVEL, LOG_FORMAT, LOG_FILE

class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support for terminal output"""
    
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[41m',   # Red background
    }
    RESET = '\033[0m'
    
    def format(self, record):
        if record.levelname in self.COLORS:
            record.levelname = f"{self.COLORS[record.levelname]}{record.levelname}{self.RESET}"
        return super().format(record)

def setup_logging(name=__name__, level=LOG_LEVEL):
    """Setup logging with both file and console handlers"""
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # File handler
    try:
        file_handler = logging.FileHandler(LOG_FILE)
        file_handler.setLevel(level)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Could not setup file logging: {e}")
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(ColoredFormatter(LOG_FORMAT))
    logger.addHandler(console_handler)
    
    return logger

# Global logger instance
logger = setup_logging('VulnerabilityScanner')

def log_finding(finding_type, url, details):
    """Log a vulnerability finding"""
    logger.warning(f"[{finding_type}] {url} - {details}")

def log_progress(current, total, task):
    """Log scanning progress"""
    percentage = (current / total * 100) if total > 0 else 0
    logger.info(f"[{task}] Progress: {current}/{total} ({percentage:.1f}%)")
