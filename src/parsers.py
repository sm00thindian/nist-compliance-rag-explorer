import re
import os
import xml.etree.ElementTree as ET
from typing import Dict, List, Any


def normalize_control_id(control_id: str) -> str:
    """Normalize control ID: uppercase, remove extra spaces, standardize parentheses."""
    if not control_id:
        return ""
    # Remove extra spaces
    control_id = re.sub(r'\s+', ' ', control_id.strip())
    # Uppercase
    control_id = control_id.upper()
    # Standardize (a) to (A), etc.
    control_id = re.sub(r'\((\d+|[a-z])\)', lambda m: f"({m.group(1).upper()})", control_id)
    return control_id


def extract_actionable_steps(description: str) -> List[str]:
    """
    Extract actionable assessment steps from NIST control description.
    Heuristic: look for sentences starting with verbs like 'Verify', 'Ensure', 'Confirm'.
    """
    if not description:
        return []

    steps = []
    sentences = re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?)\s', description)
    
    action_verbs = {
        'verify', 'ensure', 'confirm', 'check', 'review', 'validate', 'examine',
        'determine', 'identify', 'monitor', 'assess', 'test', 'inspect'
    }

    for sentence in sentences:
        sentence = sentence.strip()
        if not sentence:
            continue
        # Split on first verb
        words = sentence.split()
        if len(words) < 3:
            continue
        first_word = words[0].lower().rstrip('.,;')
        if first_word in action_verbs:
            # Clean up
            step = sentence[0].upper() + sentence[1:]
            step = re.sub(r'\s+', ' ', step)
            if not step.endswith(('.', '?')):
                step += '.'
            steps.append(step)

    # Fallback: if none found, return first sentence
    if not steps and sentences:
        first = sentences[0].strip()
        if first and not first.endswith(('.', '?')):
            first += '.'
        steps.append(first[0].upper() + first[1:])

    return steps[:10]  # Limit to reasonable number


# === EXISTING FUNCTIONS BELOW (UNCHANGED) ===
def extract_controls_from_json(catalog_json: dict) -> List[dict]:
    controls = []
    for control in catalog_json.get('controls', []):
        controls.append({
            'control_id': normalize_control_id(control['id']),
            'title': control.get('title', ''),
            'description': control.get('description', ''),
            'parameters': control.get('parameters', [])
        })
        for subcontrol in control.get('controls', []):
            controls.append({
                'control_id': normalize_control_id(subcontrol['id']),
                'title': subcontrol.get('title', ''),
                'description': subcontrol.get('description', ''),
                'parameters': subcontrol.get('parameters', [])
            })
    return controls


def extract_controls_from_excel(excel_path: str) -> List[dict]:
    import pandas as pd
    df = pd.read_excel(excel_path, sheet_name='Controls')
    controls = []
    for _, row in df.iterrows():
        controls.append({
            'control_id': normalize_control_id(str(row['Control ID'])),
            'title': str(row['Control Title']),
            'description': str(row['Control Description']),
            'parameters': []
        })
    return controls


def extract_high_baseline_controls(high_baseline_json: dict) -> List[str]:
    entries = []
    for family in high_baseline_json.get('controls', []):
        for control in family.get('controls', []):
            entries.append(f"High Baseline, {control['id']}: {control['title']}")
    return entries


def extract_assessment_procedures(assessment_json: dict) -> Dict[str, List[str]]:
    procedures = {}
    for control in assessment_json.get('controls', []):
        control_id = normalize_control_id(control['id'])
        methods = []
        for method in control.get('assessment-methods', []):
            methods.append(method.get('description', ''))
        procedures[control_id] = methods
    return procedures


def load_cci_mapping(cci_xml_path: str) -> Dict[str, str]:
    if not os.path.exists(cci_xml_path):
        return {}
    tree = ET.parse(cci_xml_path)
    root = tree.getroot()
    mapping = {}
    ns = {'cci': 'http://iase.disa.mil/cci'}
    for cci in root.findall('.//cci:cci_item', ns):
        cci_id = cci.get('id')
        nist_control = cci.find('cci:references/cci:reference[@index="800-53"]/cci:control', ns)
        if nist_control is not None:
            mapping[cci_id] = normalize_control_id(nist_control.text)
    return mapping


def load_stig_data(stig_folder: str, cci_to_nist: Dict[str, str]) -> tuple:
    all_recommendations = {}
    available_stigs = []

    if not os.path.exists(stig_folder):
        print(f"STIG folder not found: {stig_folder}")
        return all_recommendations, available_stigs

    for stig_file in os.listdir(stig_folder):
        if not stig_file.endswith('.xml'):
            continue
        file_path = os.path.join(stig_folder, stig_file)
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            ns = {'stigs': 'http://iase.disa.mil/stigs'}

            tech = root.find('.//stigs:title', ns)
            technology = tech.text if tech is not None else "Unknown"

            stig_info = {
                'file': stig_file,
                'title': root.find('.//stigs:title', ns).text if root.find('.//stigs:title', ns) is not None else "Unknown STIG",
                'technology': technology
            }
            available_stigs.append(stig_info)

            recommendations = {}
            for vuln in root.findall('.//stigs:Vuln', ns):
                rule_id = vuln.find('stigs:vuln_num', ns)
                title = vuln.find('stigs:vuln_title', ns)
                severity = vuln.find('stigs:severity', ns)
                fix = vuln.find('stigs:fixtext', ns)

                if not all([rule_id, title, fix]):
                    continue

                rule_id = rule_id.text
                title_text = title.text
                severity_text = severity.text if severity is not None else "medium"
                fix_text = fix.text if fix is not None else ""

                # Map via CCI
                cci_refs = vuln.findall('.//stigs:cci_ref', ns)
                matched_controls = set()
                for cci in cci_refs:
                    cci_id = cci.get('id')
                    if cci_id in cci_to_nist:
                        matched_controls.add(cci_to_nist[cci_id])

                for control in matched_controls:
                    if control not in recommendations:
                        recommendations[control] = []
                    recommendations[control].append({
                        'rule_id': rule_id,
                        'title': title_text,
                        'severity': severity_text,
                        'fix': fix_text
                    })

            all_recommendations[technology] = recommendations
        except Exception as e:
            print(f"Error parsing {stig_file}: {e}")

    return all_recommendations, available_stigs
