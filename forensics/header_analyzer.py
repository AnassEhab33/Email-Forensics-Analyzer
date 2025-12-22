"""
Header Analyzer Module
======================
Extracts and analyzes email headers for forensic investigation.
"""

import re
from datetime import datetime


def extract_email_address(header_value):
    """
    Extract email address from header value.
    Example: "John Doe <john@example.com>" -> "john@example.com"
    """
    if not header_value:
        return None
    
    # Try to find email in angle brackets
    match = re.search(r'<([^>]+)>', header_value)
    if match:
        return match.group(1).lower()
    
    # Try to find email pattern directly
    match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', header_value)
    if match:
        return match.group(0).lower()
    
    return header_value.lower() if '@' in header_value else None


def extract_domain(email_address):
    """
    Extract domain from email address.
    Example: "john@example.com" -> "example.com"
    """
    if not email_address or '@' not in email_address:
        return None
    return email_address.split('@')[-1].lower()


def analyze_headers(email_data):
    """
    Analyze email headers and extract forensic information.
    
    Returns:
        Dictionary with analyzed header information
    """
    analysis = {
        'from_address': extract_email_address(email_data.get('from', '')),
        'from_domain': None,
        'to_addresses': [],
        'reply_to_address': extract_email_address(email_data.get('reply_to', '')),
        'return_path_address': extract_email_address(email_data.get('return_path', '')),
        'message_id': email_data.get('message_id', ''),
        'received_chain': [],
        'x_mailer': email_data.get('x_mailer', ''),
        'important_headers': {}
    }
    
    # Extract domain from sender
    if analysis['from_address']:
        analysis['from_domain'] = extract_domain(analysis['from_address'])
    
    # Extract TO addresses
    to_field = email_data.get('to', '')
    if to_field:
        # Split by comma and extract each email
        for addr in to_field.split(','):
            email_addr = extract_email_address(addr.strip())
            if email_addr:
                analysis['to_addresses'].append(email_addr)
    
    # Analyze Received headers (email routing)
    received_headers = email_data.get('received', [])
    for received in received_headers:
        hop = parse_received_header(received)
        if hop:
            analysis['received_chain'].append(hop)
    
    # Collect important headers
    headers = email_data.get('headers', {})
    important_header_names = [
        'Authentication-Results', 'DKIM-Signature', 'Received-SPF',
        'X-Spam-Status', 'X-Originating-IP', 'X-Sender-IP',
        'X-Mailer', 'User-Agent', 'X-Priority'
    ]
    
    for header_name in important_header_names:
        if header_name in headers:
            analysis['important_headers'][header_name] = headers[header_name]
    
    return analysis


def parse_received_header(received_value):
    """
    Parse a Received header to extract routing information.
    """
    if not received_value:
        return None
    
    hop = {
        'from_server': None,
        'by_server': None,
        'timestamp': None,
        'raw': received_value[:200]  # Truncate for display
    }
    
    # Extract "from" server
    from_match = re.search(r'from\s+([^\s\(]+)', received_value, re.IGNORECASE)
    if from_match:
        hop['from_server'] = from_match.group(1)
    
    # Extract "by" server
    by_match = re.search(r'by\s+([^\s\(]+)', received_value, re.IGNORECASE)
    if by_match:
        hop['by_server'] = by_match.group(1)
    
    return hop


def get_header_summary(email_data):
    """
    Create a summary of headers for display.
    """
    headers = email_data.get('headers', {})
    
    # Headers to display (in order)
    display_headers = [
        ('From', email_data.get('from', '')),
        ('To', email_data.get('to', '')),
        ('Cc', email_data.get('cc', '')),
        ('Subject', email_data.get('subject', '')),
        ('Date', email_data.get('date', '')),
        ('Message-ID', email_data.get('message_id', '')),
        ('Reply-To', email_data.get('reply_to', '')),
        ('Return-Path', email_data.get('return_path', '')),
        ('X-Mailer', email_data.get('x_mailer', '')),
    ]
    
    return [(k, v) for k, v in display_headers if v]
