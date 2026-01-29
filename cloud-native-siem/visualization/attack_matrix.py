import json
import pandas as pd
import plotly.graph_objects as go
from plotly.subplots import make_subplots

def load_mitre_matrix():
    """Load MITRE ATT&CK matrix structure"""
    return {
        "TA0001": {"name": "Initial Access", "techniques": ["T1190", "T1133", "T1566"]},
        "TA0002": {"name": "Execution", "techniques": ["T1059", "T1203", "T1569"]},
        "TA0003": {"name": "Persistence", "techniques": ["T1136", "T1547", "T1574"]},
        "TA0004": {"name": "Privilege Escalation", "techniques": ["T1068", "T1548", "T1578"]},
        "TA0005": {"name": "Defense Evasion", "techniques": ["T1070", "T1112", "T1562"]},
        "TA0006": {"name": "Credential Access", "techniques": ["T1110", "T1555", "T1557"]},
        "TA0007": {"name": "Discovery", "techniques": ["T1083", "T1135", "T1518"]},
        "TA0008": {"name": "Lateral Movement", "techniques": ["T1021", "T1210", "T1570"]},
        "TA0009": {"name": "Collection", "techniques": ["T1113", "T1115", "T1560"]},
        "TA0010": {"name": "Exfiltration", "techniques": ["T1048", "T1567", "T1020"]},
        "TA0040": {"name": "Impact", "techniques": ["T1485", "T1486", "T1490"]}
    }

def generate_attack_matrix(events):
    """Generate interactive MITRE ATT&CK matrix visualization"""
    mitre_matrix = load_mitre_matrix()
    
    # Count techniques in events
    technique_counts = {}
    for event in events:
        techniques = event.get('mitre_techniques', [])
        for tech in techniques:
            technique_counts[tech] = technique_counts.get(tech, 0) + 1
    
    # Prepare data for heatmap
    tactics = []
    technique_names = []
    counts = []
    
    for tactic_id, tactic_info in mitre_matrix.items():
        for technique in tactic_info['techniques']:
            tactics.append(tactic_info['name'])
            technique_names.append(technique)
            counts.append(technique_counts.get(technique, 0))
    
    # Create heatmap
    fig = make_subplots(
        rows=1, cols=2,
        column_widths=[0.7, 0.3],
        specs=[[{"type": "heatmap"}, {"type": "bar"}]]
    )
    
    # Heatmap for MITRE matrix
    fig.add_trace(
        go.Heatmap(
            x=technique_names,
            y=tactics,
            z=counts,
            colorscale='Reds',
            showscale=True,
            hoverongaps=False
        ),
        row=1, col=1
    )
    
    # Bar chart for tactic distribution
    tactic_counts = {}
    for event in events:
        tactics = event.get('mitre_tactics', [])
        for tactic in tactics:
            tactic_name = mitre_matrix.get(tactic, {}).get('name', tactic)
            tactic_counts[tactic_name] = tactic_counts.get(tactic_name, 0) + 1
    
    fig.add_trace(
        go.Bar(
            x=list(tactic_counts.keys()),
            y=list(tactic_counts.values()),
            marker_color='crimson'
        ),
        row=1, col=2
    )
    
    fig.update_layout(
        title="MITRE ATT&CK Technique Heatmap",
        height=600,
        showlegend=False
    )
    
    return fig

# Save as HTML
fig = generate_attack_matrix([])
fig.write_html("mitre_attack_matrix.html")