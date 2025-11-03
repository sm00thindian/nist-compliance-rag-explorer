import re
import csv
import os
import logging
from datetime import datetime
from colorama import Fore, Style
from .text_processing import nlp
from .parsers import normalize_control_id

# ... [family_purposes, severity_colors, get_technology_name, save_checklist] ...

def generate_response(query, retrieved_docs, control_details, high_baseline_controls, all_stig_recommendations, available_stigs, assessment_procedures, cci_to_nist, generate_checklist=False):
    query_lower = query.lower()
    response = []

    # === ALWAYS DEFINE THESE (FIX UNBOUND ERROR) ===
    is_assessment_query = any(word in query_lower for word in ['assess', 'audit', 'verify', 'check'])
    is_implement_query = any(word in query_lower for word in ['implement', 'configure', 'harden', 'setup'])

    # === HANDLE CLARIFICATION RESPONSE (with technology index X) ===
    tech_index_match = re.search(r"with technology index (\d+)", query_lower)
    if tech_index_match:
        selected_idx = int(tech_index_match.group(1))
        tech_to_stig = {i+1: stig for i, stig in enumerate(available_stigs)}
        if selected_idx == 0:
            selected_techs = [stig['technology'] for stig in tech_to_stig.values()]
        elif 1 <= selected_idx <= len(tech_to_stig):
            selected_techs = [tech_to_stig[selected_idx]['technology']]
        else:
            response.append(f"{Fore.RED}Invalid technology index: {selected_idx}{Style.RESET_ALL}")
            return "\n".join(response)
        logging.debug(f"Clarification: using tech index {selected_idx} → {selected_techs}")
    else:
        # === NORMAL QUERY PROCESSING ===
        cci_match = re.search(r"(cci-\d+)", query_lower)
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

        reverse_match = re.search(r"(?:list|show)?\s*cci\s*mappings\s*for\s*(\w{2}-\d+(?:\s*[a-z])?(?:\([a-z0-9]+\))?)", query_lower)
        if reverse_match:
            control_id = normalize_control_id(reverse_match.group(1).upper())
            matching_ccis = [cci for cci, nist in cci_to_nist.items() if normalize_control_id(nist) == control_id]
            response.append(f"{Fore.CYAN}CCI Mappings for {control_id}:{Style.RESET_ALL}")
            if matching_ccis:
                response.append(f"- CCIs: {', '.join(matching_ccis)}")
            else:
                response.append("- No CCI mappings found.")
            return "\n".join(response)

        control_matches = re.findall(r"(\w{2}-\d+(?:\([a-z0-9]+\))?)", query_lower, re.IGNORECASE)
        control_ids = [normalize_control_id(m.upper()) for m in control_matches] if control_matches else []
        if not control_ids:
            control_ids = [doc.split(', ')[1].split(': ')[0] for doc in retrieved_docs if "Catalog" in doc]

        # === EXTRACT TECH KEYWORDS ===
        doc = nlp(query_lower)
        tech_keywords = []
        tech_patterns = {
            'windows': ['windows', 'microsoft', 'win', 'ms', 'windows 10', 'windows server'],
            'linux': ['linux', 'ubuntu', 'red hat', 'rhel', 'centos', 'suse', 'almalinux'],
            'ios': ['ios', 'ipad', 'apple', 'macos'],
            'android': ['android', 'google', 'samsung', 'pixel'],
            'vmware': ['vmware', 'esxi', 'vsphere'],
            'solaris': ['solaris', 'sun'],
            'splunk': ['splunk'],
            'tippingpoint': ['tippingpoint', 'trend micro'],
        }
        for token in doc:
            token_lower = token.text.lower()
            for tech, patterns in tech_patterns.items():
                if any(p in token_lower for p in patterns):
                    tech_keywords.append(tech)
                    break
        tech_keywords = list(set(tech_keywords))
        logging.debug(f"Detected tech keywords: {tech_keywords}")

        # === BUILD TECH INDEX ===
        tech_to_stig = {i+1: stig for i, stig in enumerate(available_stigs)}
        unique_techs = list(tech_to_stig.keys())

        # === FILTER BY TECH KEYWORDS ===
        filtered_techs = []
        if tech_keywords:
            for idx in unique_techs:
                stig = tech_to_stig[idx]
                title_lower = stig['title'].lower()
                if any(keyword in title_lower for keyword in tech_keywords):
                    filtered_techs.append(idx)
            if filtered_techs:
                unique_techs = filtered_techs
                logging.debug(f"Filtered to {len(unique_techs)} techs")

        # === AUTO-SELECT OR PROMPT ===
        if len(unique_techs) == 0:
            response.append(f"{Fore.YELLOW}No STIGs found for this control.{Style.RESET_ALL}")
            selected_techs = []
        elif len(unique_techs) == 1:
            selected_techs = [tech_to_stig[unique_techs[0]]['technology']]
        elif len(unique_techs) <= 3:
            response.append(f"{Fore.CYAN}Auto-selected {len(unique_techs)} matching tech(s):{Style.RESET_ALL}")
            for idx in unique_techs:
                stig = tech_to_stig[idx]
                response.append(f"- {stig['technology']} ({stig['title'][:60]}...)")
                selected_techs.append(stig['technology'])
        else:
            top_techs = unique_techs[:5]
            response.append(f"{Fore.CYAN}Multiple STIGs available ({len(unique_techs)} total). Showing top 5:{Style.RESET_ALL}")
            for i, idx in enumerate(top_techs, 1):
                stig = tech_to_stig[idx]
                response.append(f"{i}. {stig['technology']} - {stig['title'][:70]}...")
            response.append(f"{Fore.YELLOW}Next Step:{Style.RESET_ALL} Enter a number (1-{len(top_techs)}, or 0 for all) to proceed.")
            return "\n".join(response) + "\nCLARIFICATION_NEEDED"

    # === GENERATE FINAL RESPONSE (NOW SAFE) ===
    action = "Assessing" if is_assessment_query else "Implementing"
    response.append(f"{Fore.CYAN}### {action} {', '.join(control_ids)}{Style.RESET_ALL}")
    response.append(f"Based on NIST 800-53 Rev 5 and STIGs for: {', '.join(selected_techs) if selected_techs else 'N/A'}\n")

    for control_id in control_ids:
        if control_id not in control_details:
            response.append(f"{Fore.YELLOW}1. {control_id}{Style.RESET_ALL}")
            response.append(f"   - Status: Not found in NIST 800-53 Rev 5 catalog.")
            continue

        ctrl = control_details[control_id]
        response.append(f"{Fore.YELLOW}1. {control_id} - {ctrl['title']}{Style.RESET_ALL}")
        response.append(f"   - Purpose: {ctrl['description'].split('.')[0].lower()}.")

        if is_assessment_query:
            response.append(f"{Fore.CYAN}   Assessment Steps:{Style.RESET_ALL}")
            if control_id in assessment_procedures:
                for i, method in enumerate(assessment_procedures[control_id], 1):
                    response.append(f"     {i}. {method}")
            else:
                steps = extract_actionable_steps(ctrl['description'])
                for i, step in enumerate(steps, 1):
                    response.append(f"     {i}. {step}")
                if ctrl.get('parameters'):
                    response.append(f"     {len(steps)+1}. Confirm parameters: {', '.join(ctrl['parameters'])}")

            if selected_techs:
                for tech in selected_techs:
                    recs = all_stig_recommendations.get(tech, {}).get(control_id, [])
                    if recs:
                        response.append(f"{Fore.CYAN}   STIG Checks for {tech}:{Style.RESET_ALL}")
                        for i, rec in enumerate(recs, 1):
                            severity = rec.get('severity', 'medium').capitalize()
                            color = severity_colors.get(severity, Fore.WHITE)
                            response.append(f"     {i}. {rec['title']} (Rule {rec['rule_id']})")
                            response.append(f"        - {Fore.GREEN}Fix:{Style.RESET_ALL} {rec['fix'][:200]}{'...' if len(rec['fix']) > 200 else ''}")
                            response.append(f"        - {color}Severity: {severity}{Style.RESET_ALL}")
                    else:
                        response.append(f"{Fore.CYAN}   STIG Checks for {tech}:{Style.RESET_ALL} No specific checks.")

        elif is_implement_query:
            response.append(f"{Fore.CYAN}   Implementation Guidance:{Style.RESET_ALL}")
            guidance = [doc.split(': ', 1)[1] for doc in retrieved_docs if control_id in doc and "Assessment" not in doc]
            if guidance:
                for i, step in enumerate(guidance, 1):
                    response.append(f"     {i}. {step}")
            else:
                response.append(f"     1. Follow the control description to enforce this requirement.")

            if selected_techs:
                for tech in selected_techs:
                    recs = all_stig_recommendations.get(tech, {}).get(control_id, [])
                    if recs:
                        response.append(f"{Fore.CYAN}   STIG Guidance for {tech}:{Style.RESET_ALL}")
                        for i, rec in enumerate(recs, 1):
                            short_title = rec['title'][:50] + "..." if len(rec['title']) > 50 else rec['title']
                            response.append(f"     {i}. {short_title} (Rule {rec['rule_id']})")
                            response.append(f"        - {Fore.GREEN}Apply:{Style.RESET_ALL} {rec['fix'][:200]}{'...' if len(rec['fix']) > 200 else ''}")
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
