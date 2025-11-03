import re
import csv
import os
import logging
import textwrap
from datetime import datetime
from colorama import Fore, Style
from .text_processing import nlp
from .parsers import normalize_control_id

# ----------------------------------------------------------------------
#  CONSTANTS
# ----------------------------------------------------------------------
family_purposes = {
    "AC": "manage access to information systems and resources",
    "AT": "provide security awareness and training",
    "AU": "monitor and review system activities for security and compliance",
    "CA": "assess and authorize information systems",
    "CM": "manage system configurations",
    "CP": "ensure contingency planning for system resilience",
    "IA": "identify and authenticate users and systems",
    "IR": "respond to security incidents",
    "MA": "maintain information systems",
    "MP": "protect media containing sensitive information",
    "PE": "manage physical access to facilities and systems",
    "PL": "plan for security and privacy in system development",
    "PM": "manage security and privacy programs",
    "PS": "manage personnel security",
    "PT": "manage personally identifiable information (PII) processing",
    "RA": "assess and manage risks",
    "SA": "acquire and manage system development and maintenance",
    "SC": "implement system and communications protection",
    "SI": "ensure system and information integrity",
    "SR": "manage supply chain risks",
}

severity_colors = {
    'High': Fore.RED,
    'Medium': Fore.YELLOW,
    'Low': Fore.GREEN
}


# ----------------------------------------------------------------------
#  HELPERS
# ----------------------------------------------------------------------
def get_technology_name(stig):
    title = stig.get('title', 'Untitled')
    tech = stig.get('technology', title)
    if "STIG" in title and title != "Untitled STIG" and len(title.split()) > 2:
        return " ".join(word for word in title.split() if "STIG" not in word and "V" not in word and "R" not in word[:2])
    return tech


def save_checklist(control_id, steps, stig_recommendations, filename_prefix="checklist"):
    checklist_dir = "assessment_checklists"
    os.makedirs(checklist_dir, exist_ok=True)
    filename = os.path.join(checklist_dir, f"{filename_prefix}_{control_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Source", "Control/Rule", "Action", "Assessment Task", "Severity", "Expected Evidence", "Status"])

        for i, step in enumerate(steps, 1):
            task = step.lower().replace("to assess this control, verify ", "").replace("check parameters: none specified", "").strip()
            if "[assignment:" in task:
                task = task.replace("[assignment: organization-defined ", "").replace("]", "").replace("[withdrawn: incorporated into ac-6.]", "Withdrawn (see AC-6)")
                task = f"Verify {task} as defined by your organization."
            else:
                task = f"Verify {task.capitalize()}."
            writer.writerow([
                "NIST 800-53",
                control_id,
                f"Verify Compliance ({i})",
                task,
                "N/A",
                "Access control policy, logs, or config screenshots",
                "Pending"
            ])

        for tech, recs in stig_recommendations.items():
            for matched_control, rec_list in recs.items():
                for rec in rec_list:
                    fix_lines = rec['fix'].split('\n')
                    formatted_fix = []
                    for line in fix_lines:
                        line = line.strip()
                        if line and line[0].isdigit() and line[1] == '.':
                            formatted_fix.append(f"- {line}")
                        elif line and formatted_fix:
                            formatted_fix[-1] += f" {line}"
                        elif line:
                            formatted_fix.append(f"- {line}")
                    task = f"Verify {rec['title']}:\n" + "\n".join(formatted_fix)
                    writer.writerow([
                        f"STIG {tech}",
                        rec['rule_id'],
                        "Configure and Verify",
                        task,
                        rec.get('severity', 'medium').capitalize(),
                        "Configuration settings, logs, or admin console screenshots",
                        "Pending"
                    ])
    logging.info(f"Generated checklist: {filename}")
    return filename


def _get_terminal_width() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 120  # fallback


def _wrap(text: str, width: int, indent: str = "") -> str:
    """Wrap long text with indent on continuation lines."""
    if not text:
        return ""
    wrapper = textwrap.TextWrapper(width=width - len(indent), subsequent_indent=" " * len(indent))
    return "\n".join(wrapper.wrap(text))


def _parse_stig_fix(fix_text: str):
    assessment = ""
    fix = ""
    details = []
    for line in fix_text.splitlines():
        line = line.strip()
        if line.lower().startswith("assessment:"):
            assessment = line[11:].strip()
        elif line.lower().startswith("fix:"):
            fix = line[4:].strip()
        elif line:
            details.append(line)
    return assessment, fix, "\n".join(details)


def _format_stig_table(recs: list, term_width: int) -> str:
    if not recs:
        return "No specific STIG guidance."

    # === COLUMN WIDTHS ===
    rule_w = 22
    title_w = (term_width - 30) - rule_w - 12  # 12 = padding + borders
    sev_w = 8

    header = f"{Fore.CYAN}│ {'Rule ID':<{rule_w}} │ {'Title':<{title_w}} │ {'Severity':<{sev_w}} │{Style.RESET_ALL}"
    separator = f"{Fore.CYAN}├{'─' * (rule_w + 2)}┼{'─' * (title_w + 2)}┼{'─' * (sev_w + 2)}┤{Style.RESET_ALL}"

    lines = [header, separator]

    for rec in recs:
        rule = rec.get('rule_id', 'N/A')
        title = rec['title']
        sev = rec.get('severity', 'medium').capitalize()
        color = severity_colors.get(sev, Fore.WHITE)

        assessment, fix, details = _parse_stig_fix(rec['fix'])

        # === HEADER LINE (wrapped title) ===
        wrapped_title = _wrap(title, title_w)
        title_lines = wrapped_title.splitlines()
        lines.append(
            f"{Fore.CYAN}│ {rule:<{rule_w}} │ {title_lines[0]:<{title_w}} │ {color}{sev:<{sev_w}}{Style.RESET_ALL} │"
        )
        for extra in title_lines[1:]:
            lines.append(f"{Fore.CYAN}│ {'':<{rule_w}} │ {extra:<{title_w}} │ {'':<{sev_w}} │{Style.RESET_ALL}")

        # === ASSESSMENT ===
        if assessment:
            wrapped = _wrap(assessment, term_width - 10, "│ Assessment: ")
            for line in wrapped.splitlines():
                lines.append(f"{Fore.MAGENTA}{Style.BRIGHT}{line}{Style.RESET_ALL}")

        # === FIX ===
        if fix:
            wrapped = _wrap(fix, term_width - 10, "│ Fix: ")
            for line in wrapped.splitlines():
                lines.append(f"{Fore.GREEN}{Style.BRIGHT}{line}{Style.RESET_ALL}")

        # === DETAILS (BRIGHT WHITE) ===
        if details:
            wrapped = _wrap(details, term_width - 10, "│ Details: ")
            for line in wrapped.splitlines():
                lines.append(f"{Fore.WHITE}{Style.BRIGHT}{line}{Style.RESET_ALL}")

        # === ROW SEPARATOR ===
        lines.append(separator)

    # Remove last separator
    if lines and lines[-1] == separator:
        lines.pop()

    return "\n".join(lines)


# ----------------------------------------------------------------------
#  MAIN GENERATOR
# ----------------------------------------------------------------------
def generate_response(query, retrieved_docs, control_details, high_baseline_controls,
                      all_stig_recommendations, available_stigs, assessment_procedures,
                      cci_to_nist, generate_checklist=False):
    query_lower = query.lower()
    response = []

    # === ORIGINAL QUERY ===
    original_query = re.sub(r" with technology index \d+$", "", query).strip()
    original_lower = original_query.lower()

    # === QUERY TYPE & CONTROLS ===
    is_assessment_query = any(w in original_lower for w in ['assess', 'audit', 'verify', 'check'])
    is_implement_query = any(w in original_lower for w in ['implement', 'configure', 'harden', 'setup'])
    action = "Assessing" if is_assessment_query else "Implementing"

    control_matches = re.findall(r"(\w{2}-\d+(?:\([a-z0-9]+\))?)", original_lower, re.IGNORECASE)
    control_ids = [normalize_control_id(m.upper()) for m in control_matches] if control_matches else []
    if not control_ids:
        control_ids = [doc.split(', ')[1].split(': ')[0] for doc in retrieved_docs if "Catalog" in doc]

    # === CLARIFICATION RESPONSE ===
    tech_index_match = re.search(r"with technology index (\d+)", query_lower)
    if tech_index_match:
        selected_idx = int(tech_index_match.group(1))

        doc = nlp(original_lower)
        tech_keywords = []
        tech_patterns = {
            'windows': ['windows', 'microsoft', 'win', 'ms', 'windows 10', 'windows server'],
            'linux': ['linux', 'ubuntu', 'red hat', 'rhel', 'centos', 'suse', 'almalinux', 'redhat'],
            'ios': ['ios', 'ipad', 'apple', 'macos'],
            'android': ['android', 'google', 'samsung', 'pixel'],
            'vmware': ['vmware', 'esxi', 'vsphere'],
            'solaris': ['solaris', 'sun'],
            'splunk': ['splunk'],
            'tippingpoint': ['tippingpoint', 'trend micro'],
        }
        for token in doc:
            t = token.text.lower()
            for tech, pats in tech_patterns.items():
                if any(p in t for p in pats):
                    tech_keywords.append(tech)
                    break
        tech_keywords = list(set(tech_keywords))

        filtered_stigs = [
            s for s in available_stigs
            if any(kw in s['title'].lower() for kw in tech_keywords)
        ] if tech_keywords else available_stigs

        tech_to_stig = {i + 1: s for i, s in enumerate(filtered_stigs)}
        if selected_idx == 0:
            selected_techs = [s['technology'] for s in tech_to_stig.values()]
        elif 1 <= selected_idx <= len(tech_to_stig):
            selected_techs = [tech_to_stig[selected_idx]['technology']]
        else:
            response.append(f"{Fore.RED}Invalid technology index: {selected_idx}{Style.RESET_ALL}")
            return "\n".join(response)
        logging.debug(f"Clarification: using index {selected_idx} → {selected_techs}")
    else:
        # === NORMAL QUERY PROCESSING ===
        cci_match = re.search(r"(cci-\d+)", original_lower)
        if cci_match:
            cci_id = cci_match.group(1).upper()
            nist_control = cci_to_nist.get(cci_id, "Not mapped to NIST 800-53 Rev 5")
            normalized_control = normalize_control_id(nist_control)
            response.append(f"{Fore.CYAN}CCI Lookup:{Style.RESET_ALL}")
            response.append(f"- {cci_id} maps to NIST {normalized_control}")
            if normalized_control in control_details:
                ctrl = control_details[normalized_control]
                response.append(f"- **Title:** {ctrl['title']}")
                response.append(f"- **Description:** {ctrl['description']}")
            return "\n".join(response)

        reverse_match = re.search(r"(?:list|show)?\s*cci\s*mappings\s*for\s*(\w{2}-\d+(?:\s*[a-z])?(?:\([a-z0-9]+\))?)", original_lower)
        if reverse_match:
            control_id = normalize_control_id(reverse_match.group(1).upper())
            matching_ccis = [cci for cci, nist in cci_to_nist.items() if normalize_control_id(nist) == control_id]
            response.append(f"{Fore.CYAN}CCI Mappings for {control_id}:{Style.RESET_ALL}")
            if matching_ccis:
                response.append(f"- CCIs: {', '.join(matching_ccis)}")
            else:
                response.append("- No CCI mappings found.")
            return "\n".join(response)

        # === TECH KEYWORD DETECTION ===
        doc = nlp(original_lower)
        tech_keywords = []
        tech_patterns = {
            'windows': ['windows', 'microsoft', 'win', 'ms', 'windows 10', 'windows server'],
            'linux': ['linux', 'ubuntu', 'red hat', 'rhel', 'centos', 'suse', 'almalinux', 'redhat'],
            'ios': ['ios', 'ipad', 'apple', 'macos'],
            'android': ['android', 'google', 'samsung', 'pixel'],
            'vmware': ['vmware', 'esxi', 'vsphere'],
            'solaris': ['solaris', 'sun'],
            'splunk': ['splunk'],
            'tippingpoint': ['tippingpoint', 'trend micro'],
        }
        for token in doc:
            t = token.text.lower()
            for tech, pats in tech_patterns.items():
                if any(p in t for p in pats):
                    tech_keywords.append(tech)
                    break
        tech_keywords = list(set(tech_keywords))
        logging.debug(f"Detected tech keywords: {tech_keywords}")

        # === FILTER STIGS ===
        filtered_stigs = [
            s for s in available_stigs
            if any(kw in s['title'].lower() for kw in tech_keywords)
        ] if tech_keywords else available_stigs

        tech_to_stig = {i + 1: s for i, s in enumerate(filtered_stigs)}
        unique_techs = list(tech_to_stig.keys())

        # === AUTO-SELECT OR PROMPT ===
        if len(unique_techs) == 0:
            response.append(f"{Fore.YELLOW}No STIGs found for this control.{Style.RESET_ALL}")
            selected_techs = []
        elif len(unique_techs) == 1:
            selected_techs = [tech_to_stig[unique_techs[0]]['technology']]
        elif len(unique_techs) <= 3:
            response.append(f"{Fore.CYAN}Auto-selected {len(unique_techs)} matching tech(s):{Style.RESET_ALL}")
            for idx in unique_techs:
                s = tech_to_stig[idx]
                response.append(f"- {s['technology']} ({s['title'][:60]}...)")
                selected_techs.append(s['technology'])
        else:
            top = unique_techs[:5]
            response.append(f"{Fore.CYAN}Multiple STIGs available ({len(unique_techs)} total). Showing top 5:{Style.RESET_ALL}")
            for i, idx in enumerate(top, 1):
                s = tech_to_stig[idx]
                response.append(f"{i}. {s['technology']} - {s['title'][:70]}...")
            response.append(f"{Fore.YELLOW}Next Step:{Style.RESET_ALL} Enter a number (1-{len(top)}, or 0 for all) to proceed.")
            return "\n".join(response) + "\nCLARIFICATION_NEEDED"

    # === FINAL RESPONSE ===
    term_width = _get_terminal_width()
    response.append(f"{Fore.CYAN}### {action} {', '.join(control_ids)}{Style.RESET_ALL}")
    response.append(f"Based on NIST 800-53 Rev 5 and STIGs for: {', '.join(selected_techs) if selected_techs else 'N/A'}\n")

    for control_id in control_ids:
        if control_id not in control_details:
            response.append(f"{Fore.YELLOW}1. {control_id}{Style.RESET_ALL}")
            response.append(f"   - Status: Not found in NIST 800-53 Rev 5 catalog.")
            continue

        ctrl = control_details[control_id]
        response.append(f"{Fore.YELLOW}1. {control_id} - {ctrl['title']}{Style.RESET_ALL}")
        purpose = ctrl['description'].split('.')[0].lower()
        response.append(f"   - Purpose: {_wrap(purpose, term_width - 10, '     ')}")

        if is_assessment_query:
            response.append(f"{Fore.CYAN}   Assessment Steps:{Style.RESET_ALL}")
            if control_id in assessment_procedures:
                for i, m in enumerate(assessment_procedures[control_id], 1):
                    wrapped = _wrap(m, term_width - 10, f"     {i}. ")
                    response.extend(wrapped.splitlines())
            else:
                steps = extract_actionable_steps(ctrl['description'])
                for i, s in enumerate(steps, 1):
                    wrapped = _wrap(s, term_width - 10, f"     {i}. ")
                    response.extend(wrapped.splitlines())

        elif is_implement_query:
            response.append(f"{Fore.CYAN}   Implementation Guidance:{Style.RESET_ALL}")
            guidance = [doc.split(': ', 1)[1] for doc in retrieved_docs if control_id in doc and "Assessment" not in doc]
            if guidance:
                for i, g in enumerate(guidance, 1):
                    wrapped = _wrap(g, term_width - 10, f"     {i}. ")
                    response.extend(wrapped.splitlines())
            else:
                response.append(f"     1. Follow the control description to enforce this requirement.")

        # === STIG TABLE ===
        if selected_techs:
            for tech in selected_techs:
                recs = all_stig_recommendations.get(tech, {}).get(control_id, [])
                if recs:
                    response.append(f"{Fore.CYAN}   STIG Guidance for {tech}:{Style.RESET_ALL}")
                    response.append(_format_stig_table(recs, term_width))
                else:
                    response.append(f"{Fore.CYAN}   STIG Guidance for {tech}:{Style.RESET_ALL} No specific guidance.")

        if generate_checklist:
            steps = extract_actionable_steps(ctrl['description'])
            stig_recs = {
                tech: {control_id: all_stig_recommendations.get(tech, {}).get(control_id, [])}
                for tech in selected_techs
            }
            if steps or any(stig_recs.values()):
                checklist_file = save_checklist(control_id, steps, stig_recs)
                response.append(f"   - {Fore.GREEN}Checklist Saved:{Style.RESET_ALL} `{checklist_file}`")

    if len(response) <= 2:
        response.append(f"{Fore.RED}No specific information found for this query.{Style.RESET_ALL}")

    return "\n".join(response)
