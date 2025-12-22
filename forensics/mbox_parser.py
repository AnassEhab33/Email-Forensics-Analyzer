"""
MBOX Parser Module
==================
Parses MBOX email files and extracts individual email messages.
Uses Python's built-in mailbox module - no external forensic tools.
"""

import mailbox
import email
from email.header import decode_header
from datetime import datetime
import os


def decode_mime_header(header_value):
    """
    Decode MIME-encoded email headers.
    Example: =?UTF-8?B?SGVsbG8=?= becomes "Hello"
    """
    if header_value is None:
        return ""
    
    decoded_parts = []
    try:
        parts = decode_header(header_value)
        for content, charset in parts:
            if isinstance(content, bytes):
                charset = charset or 'utf-8'
                try:
                    decoded_parts.append(content.decode(charset, errors='replace'))
                except:
                    decoded_parts.append(content.decode('utf-8', errors='replace'))
            else:
                decoded_parts.append(content)
    except:
        return str(header_value)
    
    return ''.join(decoded_parts)


def parse_date(date_string):
    """
    Parse email date string into datetime object.
    Handles various date formats commonly found in emails.
    """
    if not date_string:
        return None
    
    # Common email date formats
    formats = [
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S",
        "%d %b %Y %H:%M:%S %z",
        "%d %b %Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ]
    
    # Clean up the date string
    date_string = date_string.strip()
    # Remove timezone name in parentheses like (UTC) or (EST)
    if '(' in date_string:
        date_string = date_string[:date_string.rfind('(')].strip()
    
    for fmt in formats:
        try:
            return datetime.strptime(date_string, fmt)
        except ValueError:
            continue
    
    return None


def parse_mbox_file(filepath):
    """
    Parse an MBOX file and extract all emails with their details.
    
    Args:
        filepath: Path to the MBOX file
        
    Returns:
        List of dictionaries containing email data
    """
    emails = []
    
    try:
        mbox = mailbox.mbox(filepath)
        
        for idx, message in enumerate(mbox):
            email_data = {
                'id': idx + 1,
                'from': decode_mime_header(message.get('From', '')),
                'to': decode_mime_header(message.get('To', '')),
                'cc': decode_mime_header(message.get('Cc', '')),
                'bcc': decode_mime_header(message.get('Bcc', '')),
                'subject': decode_mime_header(message.get('Subject', '(No Subject)')),
                'date': message.get('Date', ''),
                'date_parsed': parse_date(message.get('Date', '')),
                'message_id': message.get('Message-ID', ''),
                'reply_to': decode_mime_header(message.get('Reply-To', '')),
                'return_path': message.get('Return-Path', ''),
                'received': message.get_all('Received', []),
                'x_mailer': message.get('X-Mailer', ''),
                'content_type': message.get_content_type(),
                'headers': dict(message.items()),
                'body_text': '',
                'body_html': '',
                'attachments': [],
                'raw_message': message
            }
            
            # Extract body and attachments
            if message.is_multipart():
                for part in message.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get('Content-Disposition', ''))
                    
                    # Check for attachments
                    if 'attachment' in content_disposition or part.get_filename():
                        filename = part.get_filename()
                        if filename:
                            filename = decode_mime_header(filename)
                            payload = part.get_payload(decode=True)
                            email_data['attachments'].append({
                                'filename': filename,
                                'content_type': content_type,
                                'size': len(payload) if payload else 0,
                                'data': payload
                            })
                    # Extract text body
                    elif content_type == 'text/plain':
                        try:
                            charset = part.get_content_charset() or 'utf-8'
                            payload = part.get_payload(decode=True)
                            if payload:
                                email_data['body_text'] = payload.decode(charset, errors='replace')
                        except:
                            pass
                    # Extract HTML body
                    elif content_type == 'text/html':
                        try:
                            charset = part.get_content_charset() or 'utf-8'
                            payload = part.get_payload(decode=True)
                            if payload:
                                email_data['body_html'] = payload.decode(charset, errors='replace')
                        except:
                            pass
            else:
                # Single part message
                try:
                    charset = message.get_content_charset() or 'utf-8'
                    payload = message.get_payload(decode=True)
                    if payload:
                        if message.get_content_type() == 'text/html':
                            email_data['body_html'] = payload.decode(charset, errors='replace')
                        else:
                            email_data['body_text'] = payload.decode(charset, errors='replace')
                except:
                    email_data['body_text'] = str(message.get_payload())
            
            # Remove raw message before returning (not serializable)
            del email_data['raw_message']
            
            emails.append(email_data)
        
        mbox.close()
        
    except Exception as e:
        raise Exception(f"Error parsing MBOX file: {str(e)}")
    
    return emails


def get_email_statistics(emails):
    """
    Calculate statistics from parsed emails.
    """
    stats = {
        'total_emails': len(emails),
        'unique_senders': len(set(e['from'] for e in emails)),
        'unique_recipients': len(set(e['to'] for e in emails if e['to'])),
        'total_attachments': sum(len(e['attachments']) for e in emails),
        'date_range': {
            'earliest': None,
            'latest': None
        }
    }
    
    # Calculate date range
    dates = [e['date_parsed'] for e in emails if e['date_parsed']]
    if dates:
        stats['date_range']['earliest'] = min(dates).isoformat() if dates else None
        stats['date_range']['latest'] = max(dates).isoformat() if dates else None
    
    return stats
