"""
Attachment Handler Module
=========================
Extracts and analyzes email attachments for forensic investigation.
"""

import os
import hashlib
from datetime import datetime


# File type categories
FILE_CATEGORIES = {
    'documents': ['.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf', '.odt'],
    'images': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.ico'],
    'archives': ['.zip', '.rar', '.7z', '.tar', '.gz', '.bz2'],
    'executables': ['.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.dll', '.scr'],
    'media': ['.mp3', '.mp4', '.wav', '.avi', '.mov', '.mkv', '.flv'],
    'other': []
}

# Dangerous file types
DANGEROUS_EXTENSIONS = ['.exe', '.scr', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.dll', '.com', '.pif', '.hta', '.msi']


def get_file_category(filename):
    """
    Categorize file by extension.
    """
    ext = os.path.splitext(filename.lower())[1]
    
    for category, extensions in FILE_CATEGORIES.items():
        if ext in extensions:
            return category
    
    return 'other'


def is_dangerous_file(filename):
    """
    Check if file has a dangerous extension.
    """
    ext = os.path.splitext(filename.lower())[1]
    return ext in DANGEROUS_EXTENSIONS


def calculate_file_hash(data):
    """
    Calculate MD5 and SHA256 hashes of file data.
    """
    if not data:
        return {'md5': None, 'sha256': None}
    
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest()
    }


def extract_attachments(emails, output_dir):
    """
    Extract all attachments from emails to a directory.
    
    Args:
        emails: List of parsed email data
        output_dir: Directory to save attachments
        
    Returns:
        List of extracted attachment metadata
    """
    os.makedirs(output_dir, exist_ok=True)
    
    extracted = []
    
    for email_data in emails:
        email_id = email_data.get('id', 0)
        email_subject = email_data.get('subject', 'Unknown')
        email_from = email_data.get('from', 'Unknown')
        
        for attachment in email_data.get('attachments', []):
            filename = attachment.get('filename', 'unknown_file')
            data = attachment.get('data', b'')
            
            # Create unique filename to avoid overwrites
            safe_filename = f"{email_id}_{filename}"
            safe_filename = "".join(c for c in safe_filename if c.isalnum() or c in '._-')
            
            filepath = os.path.join(output_dir, safe_filename)
            
            # Save file
            if data:
                with open(filepath, 'wb') as f:
                    f.write(data)
            
            # Calculate hashes
            hashes = calculate_file_hash(data)
            
            extracted.append({
                'email_id': email_id,
                'email_subject': email_subject,
                'email_from': email_from,
                'filename': filename,
                'saved_as': safe_filename,
                'filepath': filepath,
                'size': len(data) if data else 0,
                'size_formatted': format_file_size(len(data) if data else 0),
                'content_type': attachment.get('content_type', 'unknown'),
                'category': get_file_category(filename),
                'is_dangerous': is_dangerous_file(filename),
                'md5': hashes['md5'],
                'sha256': hashes['sha256'],
                'extracted_at': datetime.now().isoformat()
            })
    
    return extracted


def format_file_size(size_bytes):
    """
    Format file size in human readable format.
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def get_attachment_statistics(extracted_attachments):
    """
    Calculate statistics about extracted attachments.
    """
    stats = {
        'total_count': len(extracted_attachments),
        'total_size': sum(a['size'] for a in extracted_attachments),
        'dangerous_count': sum(1 for a in extracted_attachments if a['is_dangerous']),
        'by_category': {},
        'by_type': {}
    }
    
    # Count by category
    for attachment in extracted_attachments:
        category = attachment['category']
        stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
        
        content_type = attachment['content_type']
        stats['by_type'][content_type] = stats['by_type'].get(content_type, 0) + 1
    
    stats['total_size_formatted'] = format_file_size(stats['total_size'])
    
    return stats
