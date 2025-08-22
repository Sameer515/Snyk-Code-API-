# Filename: snyk_code_reporter.py

import requests
import json
import getpass
import os
import re
import argparse
import sys
from datetime import datetime
from urllib.parse import urljoin, urlparse

# --- Configuration ---
SNYK_API_VERSION = "2024-07-29"
BASE_API_URL = "https://api.snyk.io"
PREVIOUS_REPORT_FILE = "snyk_report_previous.json"
DIFF_REPORT_FILE = "snyk_report_new_diff.json"

# --- Credential Loading ---
# The script now reads credentials from environment variables first.
# Set them in your terminal's profile (e.g., ~/.zshrc) for a secure, non-interactive run:
# export SNYK_TOKEN="your-token"
# export SNYK_GROUP_ID="your-group-id"
SNYK_TOKEN = os.getenv('TOKEN', '')
GROUP_ID = os.getenv('GROUP_ID', '')


def validate_snyk_url(url):
    """Validates that a URL is a legitimate Snyk API endpoint to prevent SSRF."""
    try:
        parsed = urlparse(url)
        # Only allow HTTPS connections to api.snyk.io
        if parsed.scheme != 'https' or parsed.netloc != 'api.snyk.io':
            return False
        # Validate path structure for Snyk API endpoints
        valid_paths = [
            '/rest/groups/',
            '/rest/orgs/',
            '/v1/user/me'
        ]
        return any(parsed.path.startswith(path) for path in valid_paths)
    except Exception:
        return False


def sanitize_uuid(uuid_str):
    """Sanitizes UUID input to prevent injection attacks."""
    if not uuid_str or uuid_str == 'N/A':
        return None
    # UUID format: 8-4-4-4-12 characters (hex)
    uuid_pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
    if uuid_pattern.match(uuid_str):
        return uuid_str
    return None


def sanitize_filepath(filepath):
    """Sanitizes file path to prevent path traversal attacks."""
    if not filepath:
        return None
    
    # Remove any path traversal attempts
    sanitized = os.path.basename(filepath)
    
    # Only allow alphanumeric characters, dots, hyphens, and underscores
    if not re.match(r'^[a-zA-Z0-9._-]+$', sanitized):
        return None
        
    # Prevent hidden files and files without extensions
    if sanitized.startswith('.') or '.' not in sanitized:
        return None
        
    return sanitized


def build_safe_url(base_url, path_parts):
    """Builds a safe URL by joining parts and validating the result."""
    try:
        # Join URL parts safely
        full_url = urljoin(base_url + '/', '/'.join(str(part) for part in path_parts))
        # Validate the resulting URL
        if validate_snyk_url(full_url):
            return full_url
        return None
    except Exception:
        return None


def make_safe_request(url, headers, params=None, timeout=30):
    """Makes a safe HTTP request with validated URL."""
    # Validate URL before making request
    if not validate_snyk_url(url):
        print(f"\n❌ Invalid URL detected: {url}")
        return None
        
    # Additional validation to ensure URL is safe
    if not url or not isinstance(url, str):
        print(f"\n❌ Invalid URL type or empty URL")
        return None
        
    # Final validation - ensure URL is from trusted source
    validated_url = url if validate_snyk_url(url) else None
    if not validated_url:
        print(f"\n❌ URL validation failed")
        return None
        
    try:
        return requests.get(validated_url, headers=headers, params=params, timeout=timeout)
    except requests.exceptions.RequestException as e:
        print(f"\n❌ Request failed: {e}")
        return None


def fetch_paginated_data(url, headers, params):
    """Fetches all pages for a given Snyk API endpoint."""
    all_data = []
    current_params = params.copy() if params else {}
    
    while url:
        try:
            print(f".", end="", flush=True)
            response = make_safe_request(url, headers, current_params)
            if response is None:
                return None
                
            response.raise_for_status()
            data = response.json()
            all_data.extend(data.get('data', []))
            next_path = data.get('links', {}).get('next')
            if next_path and next_path.startswith('/'):
                # Build safe URL for pagination
                url = build_safe_url(BASE_API_URL, [next_path.lstrip('/')])
                if not url:
                    print(f"\n❌ Invalid pagination URL detected: {next_path}")
                    break
            else:
                url = next_path
            current_params = None
        except requests.exceptions.HTTPError as e:
            print(f"\n❌ API Error: {e.response.status_code} - {e.response.text}")
            return None
        except requests.exceptions.RequestException as e:
            print(f"\n❌ A network error occurred: {e}")
            return None
    print("\n")
    return all_data

def get_issue_details(org_id, issue_id, headers):
    """Fetches detailed information for a single issue."""
    # Sanitize inputs
    org_id = sanitize_uuid(org_id)
    issue_id = sanitize_uuid(issue_id)
    
    if not all([org_id, issue_id]):
        return None
    
    # Build safe URL
    url = build_safe_url(BASE_API_URL, ['rest', 'orgs', org_id, 'issues', issue_id])
    if not url:
        return None
        
    params = {'version': SNYK_API_VERSION}
    try:
        response = make_safe_request(url, headers, params, timeout=30)
        if response is None:
            return None
        response.raise_for_status()
        data = response.json().get('data', {})
        return data.get('attributes')
    except (requests.exceptions.HTTPError, requests.exceptions.RequestException):
        return None

def build_project_map(group_id, headers):
    """Builds a lookup map of project IDs to their names and org info."""
    # Sanitize group_id
    group_id = sanitize_uuid(group_id)
    if not group_id:
        print("❌ Invalid Group ID provided")
        return None
        
    print("🔎 Fetching organizations and projects...")
    
    # Build safe URL for organizations
    orgs_url = build_safe_url(BASE_API_URL, ['rest', 'groups', group_id, 'orgs'])
    if not orgs_url:
        print("❌ Failed to build safe URL for organizations")
        return None
        
    orgs = fetch_paginated_data(orgs_url, headers, {'version': SNYK_API_VERSION, 'limit': 100})
    if orgs is None: return None

    project_map = {}
    for org in orgs:
        org_id = org['id']
        org_name = org['attributes']['name']
        
        # Build safe URL for projects
        projects_url = build_safe_url(BASE_API_URL, ['rest', 'orgs', org_id, 'projects'])
        if not projects_url:
            continue
            
        projects = fetch_paginated_data(projects_url, headers, {'version': SNYK_API_VERSION, 'limit': 100})
        if projects:
            for project in projects:
                project_id = project['id']
                project_name = project['attributes']['name']
                project_map[project_id] = {'name': project_name, 'org_name': org_name, 'org_id': org_id}
    
    print(f"✅ Found {len(project_map)} projects across {len(orgs)} organizations.")
    return project_map

def fetch_current_code_issues(group_id, headers, since_date, project_map):
    """Fetches all current open code issues and their details from the Snyk API."""
    # Sanitize group_id
    group_id = sanitize_uuid(group_id)
    if not group_id:
        print("❌ Invalid Group ID provided")
        return None
        
    print(f" searching for Snyk Code issues created on or after {since_date}...")
    
    # Build safe URL
    issues_url = build_safe_url(BASE_API_URL, ['rest', 'groups', group_id, 'issues'])
    if not issues_url:
        print("❌ Failed to build safe URL for issues")
        return None
        
    params = {
        'version': SNYK_API_VERSION, 'type': 'code', 'status': 'open',
        'created_at.gte': f"{since_date}T00:00:00.000Z", 'limit': 100
    }
    issues = fetch_paginated_data(issues_url, headers, params)
    if issues is None: return None
    
    total_issues = len(issues)
    print(f"✅ Found {total_issues} total open code issues. Now fetching details (this may take a while)...")
    
    enriched_issues = []
    for index, issue in enumerate(issues):
        issue_id = issue['id']
        project_id = issue['relationships']['scan_item']['data']['id']
        project_info = project_map.get(project_id, {'name': 'Unknown Project', 'org_name': 'Unknown Org', 'org_id': 'N/A'})
        org_id = project_info.get('org_id')
        
        print(f"  > Processing issue {index + 1} of {total_issues}...", end='\r', flush=True)
        issue_details = get_issue_details(org_id, issue_id, headers)
        
        file_path = "N/A"
        coordinates = issue['attributes'].get('coordinates', [])
        if coordinates and coordinates[0].get('representations'):
            file_path = coordinates[0]['representations'][0].get('file', 'N/A')
        
        enriched_issues.append({
            "issue_id": issue_id,
            "organization_id": org_id,
            "project_id": project_id,
            "organization_name": project_info['org_name'],
            "project_name": project_info['name'],
            "issue_title": issue['attributes']['title'],
            "severity": issue['attributes']['effective_severity_level'].upper(),
            "created_at": issue['attributes']['created_at'],
            "file_location": file_path,
            "issue_url": issue.get('links', {}).get('related', {}).get('href', 'N/A'),
            "details": issue_details if issue_details else {}
        })
    print(f"\n✅ Finished fetching all issue details.")
    return enriched_issues

def compare_issues(previous_issues, current_issues):
    """Compares two lists of issues and returns issues present only in the current list."""
    previous_issue_ids = {issue['issue_id'] for issue in previous_issues}
    newly_found = [issue for issue in current_issues if issue['issue_id'] not in previous_issue_ids]
    return newly_found

def load_report(filepath):
    """Safely loads a JSON report file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None

def save_report(data, filename):
    """Saves a report to a JSON file."""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"📄 Report saved to '{filename}'")

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Snyk Automated Code Issues Reporter - Fetch and analyze Snyk Code issues",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python Snykcodeissue.py --token YOUR_TOKEN --group-id YOUR_GROUP_ID
  python Snykcodeissue.py --since 2024-01-01
  python Snykcodeissue.py --help

Environment Variables:
  TOKEN or SNYK_TOKEN     - Your Snyk API token
  GROUP_ID or SNYK_GROUP_ID - Your Snyk Group ID
        """
    )
    
    parser.add_argument('--token', '-t', 
                       help='Snyk API token (overrides environment variable)')
    parser.add_argument('--group-id', '-g', 
                       help='Snyk Group ID (overrides environment variable)')
    parser.add_argument('--since', '-s', 
                       help='Start date for issue search (YYYY-MM-DD, default: today)')
    parser.add_argument('--output', '-o', 
                       help='Output file for current report (default: snyk_report_previous.json)')
    parser.add_argument('--diff-output', '-d', 
                       help='Output file for new issues diff (default: snyk_report_new_diff.json)')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress progress indicators')
    parser.add_argument('--version', '-v', action='version', version='Snyk Code Issues Reporter 1.0')
    
    return parser.parse_args()


def main():
    """Main function with improved input validation and CLI support."""
    args = parse_arguments()
    
    print("--- Snyk Automated Code Issues Reporter ---")
    
    # Use command line arguments, then environment variables, then prompt
    snyk_token = args.token or SNYK_TOKEN.strip()
    group_id = args.group_id or GROUP_ID.strip()
    
    if snyk_token and group_id:
        print("✅ Using credentials from command line or environment variables.")
    
    try:
        if not snyk_token:
            snyk_token = getpass.getpass("🔑 Enter your Snyk API token: ").strip()
        
        if not group_id:
            group_id = input("🏢 Enter your Snyk Group ID: ").strip()

        # Final check to ensure credentials are not empty
        if not snyk_token or not group_id:
            print("\n❌ Snyk Token and Group ID cannot be empty. Exiting.")
            return

        # Handle date input
        if args.since:
            since_date_str = args.since
        else:
            today_date = datetime.now().strftime('%Y-%m-%d')
            prompt = f"📅 Enter a start date (YYYY-MM-DD) [default: {today_date}]: "
            since_date_str = input(prompt).strip()

            if not since_date_str:
                since_date_str = today_date
                print(f"  > No date entered. Using today's date: {today_date}")
        
        # Validate date format
        datetime.strptime(since_date_str, '%Y-%m-%d')

    except ValueError:
        print(f"\n❌ Invalid date format for '{since_date_str}'. Please use YYYY-MM-DD. Exiting.")
        return
    except (KeyboardInterrupt, EOFError):
        print("\nOperation cancelled by user. Exiting.")
        return

    headers = {'Authorization': f'token {snyk_token}', 'Accept': 'application/vnd.api+json'}
    
    project_map = build_project_map(group_id, headers)
    if not project_map: return
    
    current_issues = fetch_current_code_issues(group_id, headers, since_date_str, project_map)
    if current_issues is None: return

    # Use custom output filenames if provided (with sanitization)
    output_file = sanitize_filepath(args.output) if args.output else PREVIOUS_REPORT_FILE
    diff_output_file = sanitize_filepath(args.diff_output) if args.diff_output else DIFF_REPORT_FILE
    
    if args.output and not output_file:
        print("❌ Invalid output filename provided. Using default.")
        output_file = PREVIOUS_REPORT_FILE
    
    if args.diff_output and not diff_output_file:
        print("❌ Invalid diff output filename provided. Using default.")
        diff_output_file = DIFF_REPORT_FILE

    previous_issues = load_report(output_file)
    
    if previous_issues is not None:
        print(f"\nComparing current results with the previous report '{output_file}'...")
        newly_found_issues = compare_issues(previous_issues, current_issues)
        
        if not newly_found_issues:
            print("\n✅ No new issues found since the last run!")
        else:
            count = len(newly_found_issues)
            print(f"\n✨ Found {count} truly new code issue(s)!")
            save_report(newly_found_issues, diff_output_file)
    else:
        print(f"\nNo previous report found. Creating a new baseline at '{output_file}'.")
        print("Run the script again in the future to find what's new since today.")

    save_report(current_issues, output_file)

if __name__ == "__main__":
    main()