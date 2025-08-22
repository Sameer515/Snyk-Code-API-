"""
Security Configuration and Utilities for Snyk Code Issues Reporter

This module provides security utilities and configuration for the Snyk reporting tools.
"""

import os
import re
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse


class SecurityConfig:
    """Security configuration and validation utilities."""
    
    # Allowed Snyk API endpoints
    ALLOWED_SNYK_PATHS = [
        '/rest/groups/',
        '/rest/orgs/',
        '/v1/user/me'
    ]
    
    # Allowed Snyk API domains
    ALLOWED_DOMAINS = ['api.snyk.io']
    
    # UUID pattern for validation
    UUID_PATTERN = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', 
        re.IGNORECASE
    )
    
    # Date pattern for validation
    DATE_PATTERN = re.compile(r'^\d{4}-\d{2}-\d{2}$')
    
    @classmethod
    def validate_snyk_url(cls, url: str) -> bool:
        """
        Validates that a URL is a legitimate Snyk API endpoint to prevent SSRF.
        
        Args:
            url: The URL to validate
            
        Returns:
            True if the URL is valid, False otherwise
        """
        try:
            parsed = urlparse(url)
            
            # Only allow HTTPS connections
            if parsed.scheme != 'https':
                return False
                
            # Only allow connections to approved domains
            if parsed.netloc not in cls.ALLOWED_DOMAINS:
                return False
                
            # Validate path structure for Snyk API endpoints
            return any(parsed.path.startswith(path) for path in cls.ALLOWED_SNYK_PATHS)
            
        except Exception:
            return False
    
    @classmethod
    def sanitize_uuid(cls, uuid_str: str) -> Optional[str]:
        """
        Sanitizes UUID input to prevent injection attacks.
        
        Args:
            uuid_str: The UUID string to sanitize
            
        Returns:
            The sanitized UUID if valid, None otherwise
        """
        if not uuid_str or uuid_str == 'N/A':
            return None
            
        if cls.UUID_PATTERN.match(uuid_str):
            return uuid_str
            
        return None
    
    @classmethod
    def validate_date_format(cls, date_str: str) -> bool:
        """
        Validates date format (YYYY-MM-DD).
        
        Args:
            date_str: The date string to validate
            
        Returns:
            True if the date format is valid, False otherwise
        """
        return bool(cls.DATE_PATTERN.match(date_str))
    
    @classmethod
    def sanitize_input(cls, input_str: str, max_length: int = 1000) -> Optional[str]:
        """
        Sanitizes general input to prevent injection attacks.
        
        Args:
            input_str: The input string to sanitize
            max_length: Maximum allowed length
            
        Returns:
            The sanitized input if valid, None otherwise
        """
        if not input_str:
            return None
            
        # Remove any null bytes or control characters
        sanitized = ''.join(char for char in input_str if ord(char) >= 32)
        
        # Check length
        if len(sanitized) > max_length:
            return None
            
        return sanitized.strip()
    
    @classmethod
    def get_secure_headers(cls, token: str) -> Dict[str, str]:
        """
        Creates secure headers for API requests.
        
        Args:
            token: The API token
            
        Returns:
            Dictionary of secure headers
        """
        return {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.api+json',
            'User-Agent': 'SnykCodeIssuesReporter/1.0',
            'Content-Type': 'application/json'
        }


class LicenseManager:
    """Manages license compliance for dependencies."""
    
    # Known license issues and their severity
    LICENSE_ISSUES = {
        'MPL-2.0': {
            'severity': 'medium',
            'description': 'Mozilla Public License 2.0',
            'recommendation': 'Review license terms for compliance with your project requirements'
        }
    }
    
    @classmethod
    def check_license_compliance(cls, license_name: str) -> Dict[str, Any]:
        """
        Checks license compliance for a given license.
        
        Args:
            license_name: The license name to check
            
        Returns:
            Dictionary with compliance information
        """
        if license_name in cls.LICENSE_ISSUES:
            return cls.LICENSE_ISSUES[license_name]
        
        return {
            'severity': 'low',
            'description': f'License: {license_name}',
            'recommendation': 'Review license terms for compliance'
        }


def log_security_event(event_type: str, details: str, severity: str = 'info'):
    """
    Logs security events for monitoring and auditing.
    
    Args:
        event_type: Type of security event
        details: Details about the event
        severity: Severity level (info, warning, error)
    """
    timestamp = __import__('datetime').datetime.now().isoformat()
    log_entry = f"[{timestamp}] [{severity.upper()}] {event_type}: {details}"
    
    # In a production environment, this would go to a proper logging system
    print(f"🔒 SECURITY: {log_entry}")


def validate_environment_variables() -> Dict[str, str]:
    """
    Validates and returns secure environment variables.
    
    Returns:
        Dictionary of validated environment variables
    """
    required_vars = ['TOKEN', 'GROUP_ID']
    validated_vars = {}
    
    for var in required_vars:
        value = os.getenv(var, '').strip()
        if not value:
            log_security_event('missing_env_var', f'Required environment variable {var} is not set', 'warning')
        else:
            validated_vars[var] = value
    
    return validated_vars
