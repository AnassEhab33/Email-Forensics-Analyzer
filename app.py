"""
Email Forensics Analyzer - Flask Web Application
=================================================
A comprehensive email forensics tool for investigating phishing campaigns.
Features: MBOX parsing, header analysis, spoofing detection, interaction graphs.

Project: Digital Forensics Course
"""

from flask import Flask, render_template, request, redirect, url_for, jsonify, send_from_directory
import os
import json
from datetime import datetime

# Import forensics modules
from forensics.mbox_parser import parse_mbox_file, get_email_statistics
from forensics.header_analyzer import analyze_headers, get_header_summary
from forensics.spoofing_detector import detect_spoofing, get_spoofing_summary
from forensics.interaction_graph import build_interaction_graph
from forensics.attachment_handler import extract_attachments, get_attachment_statistics

app = Flask(__name__)
app.config['SECRET_KEY'] = 'email-forensics-2024'
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['EXTRACTED_FOLDER'] = os.path.join(os.path.dirname(__file__), 'extracted')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['EXTRACTED_FOLDER'], exist_ok=True)

# Global storage for analysis results
analysis_results = None


@app.route('/')
def index():
    """Home page with file upload."""
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and start analysis."""
    global analysis_results
    
    if 'mbox_file' not in request.files:
        return redirect(url_for('index'))
    
    file = request.files['mbox_file']
    
    if file.filename == '':
        return redirect(url_for('index'))
    
    if file:
        # Save uploaded file
        filename = f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.mbox"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Parse MBOX file
            emails = parse_mbox_file(filepath)
            
            # Analyze each email
            analyzed_emails = []
            for email_data in emails:
                header_analysis = analyze_headers(email_data)
                spoofing_result = detect_spoofing(email_data, header_analysis)
                
                analyzed_emails.append({
                    'data': email_data,
                    'headers': header_analysis,
                    'spoofing': spoofing_result,
                    'header_summary': get_header_summary(email_data)
                })
            
            # Extract attachments
            extracted_attachments = extract_attachments(emails, app.config['EXTRACTED_FOLDER'])
            
            # Build interaction graph
            interaction_graph = build_interaction_graph(emails)
            
            # Get statistics
            email_stats = get_email_statistics(emails)
            spoofing_summary = get_spoofing_summary(analyzed_emails)
            attachment_stats = get_attachment_statistics(extracted_attachments)
            
            # Store results
            analysis_results = {
                'emails': analyzed_emails,
                'email_stats': email_stats,
                'spoofing_summary': spoofing_summary,
                'interaction_graph': interaction_graph,
                'attachments': extracted_attachments,
                'attachment_stats': attachment_stats,
                'analyzed_at': datetime.now().isoformat(),
                'filename': file.filename
            }
            
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            return render_template('index.html', error=str(e))
    
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    """Main analysis dashboard."""
    global analysis_results
    
    if analysis_results is None:
        return redirect(url_for('index'))
    
    return render_template('dashboard.html', 
                         results=analysis_results,
                         graph_data=json.dumps(analysis_results['interaction_graph']))


@app.route('/email/<int:email_id>')
def email_detail(email_id):
    """View details of a specific email."""
    global analysis_results
    
    if analysis_results is None:
        return redirect(url_for('index'))
    
    # Find the email
    email = None
    for e in analysis_results['emails']:
        if e['data']['id'] == email_id:
            email = e
            break
    
    if email is None:
        return redirect(url_for('dashboard'))
    
    return render_template('email_detail.html', email=email, results=analysis_results)


@app.route('/attachments')
def attachments_view():
    """View all extracted attachments."""
    global analysis_results
    
    if analysis_results is None:
        return redirect(url_for('index'))
    
    return render_template('attachments.html', 
                         attachments=analysis_results['attachments'],
                         stats=analysis_results['attachment_stats'])


@app.route('/download/<filename>')
def download_attachment(filename):
    """Download an extracted attachment."""
    return send_from_directory(app.config['EXTRACTED_FOLDER'], filename)


@app.route('/api/graph-data')
def api_graph_data():
    """Return graph data as JSON for visualization."""
    global analysis_results
    
    if analysis_results is None:
        return jsonify({'error': 'No analysis data available'})
    
    return jsonify(analysis_results['interaction_graph'])


@app.route('/reset')
def reset():
    """Reset analysis and start over."""
    global analysis_results
    analysis_results = None
    return redirect(url_for('index'))


if __name__ == '__main__':
    print("\n" + "="*60)
    print("   📧 EMAIL FORENSICS ANALYZER")
    print("   Digital Forensics Investigation Tool")
    print("="*60)
    print("\n🌐 Open your browser and go to: http://localhost:5000\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
