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
def _get_control_id(control: dict) -> str:
    return normalize_control_id(
        control.get('control_id') or control.get('id') or control.get('controlId') or ''
    )


def _get_subcontrols(control: dict) -> list:
    return control.get('controls', []) if isinstance(control.get('controls', []), list) else []


def _gather_controls(controls_data: list) -> List[dict]:
    controls = []
    for control in controls_data:
        control_id = _get_control_id(control)
        if not control_id:
            continue
        controls.append({
            'control_id': control_id,
            'title': control.get('title', ''),
            'description': control.get('description', ''),
            'parameters': control.get('parameters', [])
        })
        for subcontrol in _get_subcontrols(control):
            subcontrol_id = _get_control_id(subcontrol)
            if not subcontrol_id:
                continue
            controls.append({
                'control_id': subcontrol_id,
                'title': subcontrol.get('title', ''),
                'description': subcontrol.get('description', ''),
                'parameters': subcontrol.get('parameters', [])
            })
    return controls


def extract_controls_from_json(catalog_json: dict) -> List[dict]:
    controls = []
    if isinstance(catalog_json.get('controls'), list):
        controls = _gather_controls(catalog_json['controls'])
    elif isinstance(catalog_json.get('catalog'), dict):
        controls = _gather_controls(catalog_json['catalog'].get('controls', []))
    else:
        # Try to find a controls list anywhere in the JSON payload
        for value in catalog_json.values():
            if isinstance(value, list) and value and isinstance(value[0], dict) and ('control_id' in value[0] or 'id' in value[0]):
                controls = _gather_controls(value)
                break
    return controls
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
    controls = []
    if isinstance(high_baseline_json.get('controls'), list):
        controls = high_baseline_json['controls']
    elif isinstance(high_baseline_json.get('high-baseline'), dict):
        controls = high_baseline_json['high-baseline'].get('controls', [])

    for control in controls:
        control_id = control.get('control_id') or control.get('id')
        baseline = control.get('baseline', '')
        if control_id:
            entries.append(f"High Baseline, {normalize_control_id(control_id)}: {baseline}")
    return entries


def extract_assessment_procedures(assessment_json: dict) -> Dict[str, List[str]]:
    procedures = {}
    controls = []
    if isinstance(assessment_json.get('controls'), list):
        controls = assessment_json['controls']
    elif isinstance(assessment_json.get('assessment-procedures'), list):
        controls = assessment_json['assessment-procedures']

    for control in controls:
        control_id = _get_control_id(control)
        if not control_id:
            continue
        methods = []
        for method in control.get('assessment-methods', []) or control.get('procedures', []):
            if isinstance(method, dict):
                methods.append(
                    method.get('description') or
                    method.get('assessment_objective') or
                    method.get('assessment_procedure') or
                    ''
                )
            elif isinstance(method, str):
                methods.append(method)
        procedures[control_id] = [m for m in methods if m]
    return procedures


def _strip_namespace(tag: str) -> str:
    return tag.split('}', 1)[-1] if '}' in tag else tag


def _find_child_text(parent: ET.Element, child_name: str) -> str | None:
    for child in parent:
        if _strip_namespace(child.tag) == child_name and child.text:
            return child.text.strip()
    return None


def _find_children(parent: ET.Element, child_name: str) -> list[ET.Element]:
    return [child for child in parent if _strip_namespace(child.tag) == child_name]


def load_cci_mapping(cci_xml_path: str) -> Dict[str, str]:
    if not os.path.exists(cci_xml_path):
        return {}

    tree = ET.parse(cci_xml_path)
    root = tree.getroot()
    mapping = {}

    for item in root.iter():
        if _strip_namespace(item.tag) != 'cci_item':
            continue

        cci_id = None
        control_id = None
        for child in item:
            tag = _strip_namespace(child.tag)
            if tag == 'cci_id' and child.text:
                cci_id = child.text.strip()
            elif tag in {'nist_control', 'nist_control_id', 'control'} and child.text:
                control_id = child.text.strip()

        if cci_id and control_id:
            mapping[cci_id] = normalize_control_id(control_id)
            continue

        nist_control = item.find('.//cci:references/cci:reference[@index="800-53"]/cci:control',
                                 {'cci': 'http://iase.disa.mil/cci'})
        if nist_control is not None and nist_control.text:
            mapping[item.get('id')] = normalize_control_id(nist_control.text)

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

            title = _find_child_text(root, 'title') or 'Unknown STIG'
            technology = title
            stig_info = {
                'file': stig_file,
                'title': title,
                'technology': technology
            }
            available_stigs.append(stig_info)

            recommendations = {}
            for rule in root.iter():
                if _strip_namespace(rule.tag) != 'Rule':
                    continue

                rule_id = rule.get('id', 'unknown-rule')
                title_text = _find_child_text(rule, 'title') or 'Unknown rule title'
                severity_text = _find_child_text(rule, 'severity') or 'medium'
                fix_text = _find_child_text(rule, 'fixtext') or ''

                matched_controls = set()
                for ident in rule.iter():
                    if _strip_namespace(ident.tag) != 'ident':
                        continue
                    system_attr = ident.get('system', '')
                    if 'cci' not in system_attr.lower():
                        continue
                    if ident.text:
                        cci_id = ident.text.strip()
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
