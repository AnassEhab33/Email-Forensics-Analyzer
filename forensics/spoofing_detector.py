"""
Spoofing Detector Module
========================
Detects email spoofing indicators for forensic investigation.
Identifies potential phishing and fraudulent emails.
"""

import re
from .header_analyzer import extract_email_address, extract_domain


# Suspicious domain patterns commonly used in phishing
SUSPICIOUS_PATTERNS = [
    r'paypa[l1]',           # PayPal typosquatting
    r'amaz[o0]n',           # Amazon typosquatting
    r'g[o0][o0]gle',        # Google typosquatting
    r'micr[o0]s[o0]ft',     # Microsoft typosquatting
    r'app[l1]e',            # Apple typosquatting
    r'bank.*login',          # Generic bank phishing
    r'secure.*update',       # Fake security updates
    r'verify.*account',      # Account verification scams
]

# Suspicious file extensions in attachments
SUSPICIOUS_EXTENSIONS = [
    '.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js',
    '.jar', '.msi', '.dll', '.com', '.pif', '.hta'
]

# Suspicious words in subject lines
PHISHING_KEYWORDS = [
    'urgent', 'immediate action', 'verify your account',
    'suspend', 'confirm your identity', 'unusual activity',
    'password expire', 'update your information', 'click here',
    'act now', 'limited time', 'winner', 'congratulations',
    'claim your prize', 'security alert', 'unauthorized access'
]


def detect_spoofing(email_data, header_analysis):
    """
    Detect spoofing indicators in an email.
    
    Args:
        email_data: Parsed email data from mbox_parser
        header_analysis: Analyzed headers from header_analyzer
        
    Returns:
        Dictionary with spoofing detection results
    """
    indicators = []
    risk_level = 'LOW'  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score = 0
    
    from_address = header_analysis.get('from_address', '')
    from_domain = header_analysis.get('from_domain', '')
    reply_to = header_analysis.get('reply_to_address', '')
    return_path = header_analysis.get('return_path_address', '')
    
    # ============================================
    # CHECK 1: From vs Return-Path Mismatch
    # ============================================
    if return_path and from_address:
        return_path_clean = return_path.strip('<>').lower()
        if return_path_clean != from_address:
            return_path_domain = extract_domain(return_path_clean)
            if return_path_domain != from_domain:
                indicators.append({
                    'type': 'DOMAIN_MISMATCH',
                    'severity': 'HIGH',
                    'title': 'From/Return-Path Domain Mismatch',
                    'description': f'The sender domain ({from_domain}) does not match the return path domain ({return_path_domain}). This is a strong indicator of email spoofing.',
                    'from': from_address,
                    'return_path': return_path_clean
                })
                risk_score += 30
    
    # ============================================
    # CHECK 2: From vs Reply-To Mismatch
    # ============================================
    if reply_to and from_address and reply_to != from_address:
        reply_to_domain = extract_domain(reply_to)
        if reply_to_domain != from_domain:
            indicators.append({
                'type': 'REPLY_TO_MISMATCH',
                'severity': 'MEDIUM',
                'title': 'From/Reply-To Domain Mismatch',
                'description': f'Replies will go to a different domain ({reply_to_domain}) than the apparent sender ({from_domain}). This could indicate a phishing attempt.',
                'from': from_address,
                'reply_to': reply_to
            })
            risk_score += 20
    
    # ============================================
    # CHECK 3: Suspicious Domain Patterns
    # ============================================
    if from_domain:
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, from_domain, re.IGNORECASE):
                indicators.append({
                    'type': 'SUSPICIOUS_DOMAIN',
                    'severity': 'HIGH',
                    'title': 'Suspicious Domain Pattern',
                    'description': f'The sender domain "{from_domain}" matches a known typosquatting or phishing pattern.',
                    'domain': from_domain
                })
                risk_score += 25
                break
    
    # ============================================
    # CHECK 4: Suspicious Attachments
    # ============================================
    attachments = email_data.get('attachments', [])
    for attachment in attachments:
        filename = attachment.get('filename', '').lower()
        for ext in SUSPICIOUS_EXTENSIONS:
            if filename.endswith(ext):
                indicators.append({
                    'type': 'SUSPICIOUS_ATTACHMENT',
                    'severity': 'CRITICAL',
                    'title': 'Dangerous Attachment Type',
                    'description': f'The email contains an executable attachment: "{attachment["filename"]}". This is commonly used in malware distribution.',
                    'filename': attachment['filename']
                })
                risk_score += 40
                break
    
    # ============================================
    # CHECK 5: Phishing Keywords in Subject
    # ============================================
    subject = email_data.get('subject', '').lower()
    found_keywords = []
    for keyword in PHISHING_KEYWORDS:
        if keyword.lower() in subject:
            found_keywords.append(keyword)
    
    if found_keywords:
        indicators.append({
            'type': 'PHISHING_KEYWORDS',
            'severity': 'MEDIUM',
            'title': 'Suspicious Subject Line',
            'description': f'The subject line contains phishing-related keywords: {", ".join(found_keywords)}',
            'keywords': found_keywords
        })
        risk_score += 15
    
    # ============================================
    # CHECK 6: Missing Message-ID
    # ============================================
    message_id = header_analysis.get('message_id', '')
    if not message_id:
        indicators.append({
            'type': 'MISSING_MESSAGE_ID',
            'severity': 'LOW',
            'title': 'Missing Message-ID Header',
            'description': 'The email is missing a Message-ID header. Legitimate mail servers usually include this.',
        })
        risk_score += 10
    
    # ============================================
    # CHECK 7: Authentication Failures (SPF/DKIM)
    # ============================================
    headers = email_data.get('headers', {})
    auth_results = headers.get('Authentication-Results', '')
    received_spf = headers.get('Received-SPF', '')
    
    if 'fail' in auth_results.lower() or 'fail' in received_spf.lower():
        indicators.append({
            'type': 'AUTH_FAILURE',
            'severity': 'HIGH',
            'title': 'Email Authentication Failed',
            'description': 'SPF or DKIM authentication has failed. The email may not be from the claimed sender.',
            'auth_result': auth_results or received_spf
        })
        risk_score += 35
    elif 'softfail' in received_spf.lower():
        indicators.append({
            'type': 'AUTH_SOFTFAIL',
            'severity': 'MEDIUM',
            'title': 'Email Authentication Soft Fail',
            'description': 'SPF authentication returned a soft fail. The sender may not be authorized.',
            'auth_result': received_spf
        })
        risk_score += 15
    
    # ============================================
    # Determine Overall Risk Level
    # ============================================
    if risk_score >= 60:
        risk_level = 'CRITICAL'
    elif risk_score >= 40:
        risk_level = 'HIGH'
    elif risk_score >= 20:
        risk_level = 'MEDIUM'
    else:
        risk_level = 'LOW'
    
    return {
        'risk_level': risk_level,
        'risk_score': min(risk_score, 100),  # Cap at 100
        'indicators': indicators,
        'is_suspicious': len(indicators) > 0,
        'indicator_count': len(indicators)
    }


def get_spoofing_summary(emails_analysis):
    """
    Generate a summary of spoofing detection across all emails.
    """
    summary = {
        'total_analyzed': len(emails_analysis),
        'critical_count': 0,
        'high_count': 0,
        'medium_count': 0,
        'low_count': 0,
        'clean_count': 0,
        'indicator_types': {}
    }
    
    for analysis in emails_analysis:
        spoofing = analysis.get('spoofing', {})
        risk_level = spoofing.get('risk_level', 'LOW')
        
        if risk_level == 'CRITICAL':
            summary['critical_count'] += 1
        elif risk_level == 'HIGH':
            summary['high_count'] += 1
        elif risk_level == 'MEDIUM':
            summary['medium_count'] += 1
        elif len(spoofing.get('indicators', [])) == 0:
            summary['clean_count'] += 1
        else:
            summary['low_count'] += 1
        
        # Count indicator types
        for indicator in spoofing.get('indicators', []):
            indicator_type = indicator.get('type', 'UNKNOWN')
            summary['indicator_types'][indicator_type] = \
                summary['indicator_types'].get(indicator_type, 0) + 1
    
    return summary
