"""
Interaction Graph Module
========================
Analyzes sender/receiver relationships and generates 
graph data for visualization.
"""

from collections import defaultdict
from .header_analyzer import extract_email_address


def build_interaction_graph(emails):
    """
    Build a graph of email interactions between senders and receivers.
    
    Returns:
        Dictionary with nodes and edges for visualization
    """
    # Track all unique email addresses
    addresses = set()
    
    # Track interactions: (sender, receiver) -> count
    interactions = defaultdict(int)
    
    # Track email counts per address
    sent_count = defaultdict(int)
    received_count = defaultdict(int)
    
    for email_data in emails:
        sender = extract_email_address(email_data.get('from', ''))
        
        if sender:
            addresses.add(sender)
            sent_count[sender] += 1
            
            # Process TO recipients
            to_field = email_data.get('to', '')
            if to_field:
                for addr in to_field.split(','):
                    recipient = extract_email_address(addr.strip())
                    if recipient:
                        addresses.add(recipient)
                        received_count[recipient] += 1
                        interactions[(sender, recipient)] += 1
            
            # Process CC recipients
            cc_field = email_data.get('cc', '')
            if cc_field:
                for addr in cc_field.split(','):
                    recipient = extract_email_address(addr.strip())
                    if recipient:
                        addresses.add(recipient)
                        received_count[recipient] += 1
                        interactions[(sender, recipient)] += 1
    
    # Build nodes
    nodes = []
    for i, address in enumerate(addresses):
        nodes.append({
            'id': i,
            'label': address.split('@')[0][:15],  # Show username only
            'email': address,
            'sent': sent_count[address],
            'received': received_count[address],
            'total': sent_count[address] + received_count[address],
            'title': f"{address}\nSent: {sent_count[address]}, Received: {received_count[address]}"
        })
    
    # Create address to id mapping
    addr_to_id = {node['email']: node['id'] for node in nodes}
    
    # Build edges
    edges = []
    for (sender, receiver), count in interactions.items():
        if sender in addr_to_id and receiver in addr_to_id:
            edges.append({
                'from': addr_to_id[sender],
                'to': addr_to_id[receiver],
                'value': count,
                'title': f"{count} email(s)",
                'arrows': 'to'
            })
    
    return {
        'nodes': nodes,
        'edges': edges,
        'stats': {
            'total_addresses': len(addresses),
            'total_interactions': sum(interactions.values()),
            'top_senders': get_top_addresses(sent_count, 5),
            'top_receivers': get_top_addresses(received_count, 5)
        }
    }


def get_top_addresses(count_dict, limit=5):
    """
    Get top addresses by count.
    """
    sorted_items = sorted(count_dict.items(), key=lambda x: x[1], reverse=True)
    return [{'address': addr, 'count': count} for addr, count in sorted_items[:limit]]


def get_interaction_matrix(emails):
    """
    Create an interaction matrix for detailed analysis.
    """
    # Track all unique addresses
    addresses = set()
    interactions = defaultdict(lambda: defaultdict(int))
    
    for email_data in emails:
        sender = extract_email_address(email_data.get('from', ''))
        if not sender:
            continue
            
        addresses.add(sender)
        
        to_field = email_data.get('to', '')
        if to_field:
            for addr in to_field.split(','):
                recipient = extract_email_address(addr.strip())
                if recipient:
                    addresses.add(recipient)
                    interactions[sender][recipient] += 1
    
    address_list = sorted(addresses)
    
    matrix = []
    for sender in address_list:
        row = []
        for receiver in address_list:
            row.append(interactions[sender][receiver])
        matrix.append(row)
    
    return {
        'addresses': address_list,
        'matrix': matrix
    }
