# Filename: daily_check.py

import requests
import json
import getpass
import os
import re
import argparse
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin, urlparse

# --- Configuration ---
SNYK_API_VERSION = "2024-07-29"
DB_FILE = "snyk_code_issues_db.json"
REPORT_FILE = "daily_snyk_code_issues_report.json"
DEFAULT_HISTORY_START_DATE = "2020-01-01"

# --- Credential Loading ---
BASE_API_URL = os.getenv('SNYK_API_URL', 'https://api.snyk.io').strip('/')
SNYK_TOKEN = os.getenv('SNYK_TOKEN', '') or os.getenv('TOKEN', '')
GROUP_ID = os.getenv('SNYK_GROUP_ID', '') or os.getenv('GROUP_ID', '')


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


def validate_token(headers):
    """Checks if the API token itself is valid using the v1 API."""
    print("🔐 Validating API token...")
    
    # Build safe URL for token validation
    url = build_safe_url(BASE_API_URL, ['v1', 'user', 'me'])
    if not url:
        print("❌ Failed to build safe URL for token validation")
        return False
        
    v1_headers = {'Authorization': headers['Authorization']}
    try:
        response = make_safe_request(url, v1_headers, timeout=10)
        if response is None:
            return False
        response.raise_for_status()
        email = response.json().get('email', 'Unknown User')
        print(f"✅ Token is valid for user: {email}")
        return True
    except requests.exceptions.HTTPError as e:
        if e.response.status_code in [401, 403]:
            print("❌ Token Validation Failed: The Snyk API Token is invalid or has expired.")
        else:
            print(f"❌ API Error during token validation: {e.response.status_code}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"❌ A network error occurred during token validation: {e}")
        return False


def fetch_paginated_data(url, headers, params):
    """Fetches all pages for a given Snyk API endpoint."""
    all_data = []
    current_params = params.copy() if params else {}
    while url:
        try:
            print(f".", end="", flush=True)
            response = make_safe_request(url, headers, current_params, timeout=30)
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
    print()
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
        return response.json().get('data', {}).get('attributes')
    except (requests.exceptions.HTTPError, requests.exceptions.RequestException):
        return None


def load_db_file(filepath):
    """Safely loads the JSON database file."""
    if not os.path.exists(filepath):
        return None, []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('last_updated'), data.get('issues', [])
    except (json.JSONDecodeError):
        return None, []


def save_db_file(issues, filename):
    """Saves the database with a new timestamp."""
    payload = {
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "issues": issues
    }
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=4, ensure_ascii=False)
    print(f"📄 Database file '{filename}' has been updated.")


def save_report_file(issues, filename):
    """Saves the report file (a simple list of issues)."""
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(issues, f, indent=4, ensure_ascii=False)
    print(f"📄 Report saved to '{filename}'")


def update_database_from_snyk(headers, group_id, db_issues):
    """Fetches new issues from Snyk and merges them into the local DB."""
    # Sanitize group_id
    group_id = sanitize_uuid(group_id)
    if not group_id:
        print("❌ Invalid Group ID provided")
        return None
        
    db_issue_ids = {issue['issue_id'] for issue in db_issues}
    latest_date = DEFAULT_HISTORY_START_DATE
    if db_issues:
        latest_issue = max(db_issues, key=lambda x: x['created_at'])
        latest_date_dt = datetime.fromisoformat(latest_issue['created_at'].replace('Z', '+00:00'))
        latest_date = (latest_date_dt + timedelta(seconds=1)).strftime('%Y-%m-%d')
    
    print(f"🔎 Syncing with Snyk API for issues created since {latest_date}...")
    
    # Build safe URL
    issues_url = build_safe_url(BASE_API_URL, ['rest', 'groups', group_id, 'issues'])
    if not issues_url:
        print("❌ Failed to build safe URL for issues")
        return None
        
    params = {
        'version': SNYK_API_VERSION, 'type': 'code', 'status': 'open',
        'created_at.gte': f"{latest_date}T00:00:00.000Z", 'limit': 100
    }
    new_issues_from_api = fetch_paginated_data(issues_url, headers, params)
    if new_issues_from_api is None: return None

    truly_new_issues = [issue for issue in new_issues_from_api if issue['id'] not in db_issue_ids]
    if not truly_new_issues:
        print("✅ Database is already up-to-date.")
        return db_issues

    total_new = len(truly_new_issues)
    print(f"✅ Found {total_new} new issues from Snyk. Fetching details...")
    project_map = build_project_map(group_id, headers)
    if not project_map: return db_issues

    for index, issue in enumerate(truly_new_issues):
        print(f"  > Processing issue {index + 1} of {total_new}...", end='\r', flush=True)
        project_id = issue['relationships']['scan_item']['data']['id']
        project_info = project_map.get(project_id, {'name': 'Unknown', 'org_name': 'Unknown', 'org_id': 'N/A'})
        org_id = project_info.get('org_id')
        issue_details = get_issue_details(org_id, issue['id'], headers)
        db_issues.append({
            "issue_id": issue['id'], "organization_id": org_id, "project_id": project_id,
            "organization_name": project_info['org_name'], "project_name": project_info['name'],
            "issue_title": issue['attributes']['title'], "severity": issue['attributes']['effective_severity_level'].upper(),
            "created_at": issue['attributes']['created_at'], "details": issue_details if issue_details else {}
        })
    print(f"\n✅ Database sync complete. Total issues in DB: {len(db_issues)}.")
    return db_issues


def build_project_map(group_id, headers):
    """Builds a project lookup map, but only if needed."""
    # Sanitize group_id
    group_id = sanitize_uuid(group_id)
    if not group_id:
        print("❌ Invalid Group ID provided")
        return None
        
    print("  > Building project map...")
    
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
        
        # Build safe URL for projects
        projects_url = build_safe_url(BASE_API_URL, ['rest', 'orgs', org_id, 'projects'])
        if not projects_url:
            continue
            
        projects = fetch_paginated_data(projects_url, headers, {'version': SNYK_API_VERSION, 'limit': 100})
        if projects:
            for project in projects:
                project_map[project['id']] = {'name': project['attributes']['name'], 'org_name': org['attributes']['name'], 'org_id': org['id']}
    return project_map


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Daily Snyk Code Issues Check - Maintain local database and generate reports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python daily_check.py --token YOUR_TOKEN --group-id YOUR_GROUP_ID
  python daily_check.py --since 2024-01-01 --no-sync
  python daily_check.py --help

Environment Variables:
  SNYK_TOKEN or TOKEN       - Your Snyk API token
  SNYK_GROUP_ID or GROUP_ID - Your Snyk Group ID
  SNYK_API_URL             - Snyk API URL (default: https://api.snyk.io)
        """
    )
    
    parser.add_argument('--token', '-t', 
                       help='Snyk API token (overrides environment variable)')
    parser.add_argument('--group-id', '-g', 
                       help='Snyk Group ID (overrides environment variable)')
    parser.add_argument('--since', '-s', 
                       help='Start date for report generation (YYYY-MM-DD, default: today)')
    parser.add_argument('--db-file', 
                       help='Database file path (default: snyk_code_issues_db.json)')
    parser.add_argument('--report-file', '-r',
                       help='Report output file (default: daily_snyk_code_issues_report.json)')
    parser.add_argument('--no-sync', action='store_true',
                       help='Skip database sync with Snyk API')
    parser.add_argument('--force-sync', action='store_true',
                       help='Force database sync even if already updated today')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress progress indicators')
    parser.add_argument('--version', '-v', action='version', version='Daily Snyk Code Issues Check 1.0')
    
    return parser.parse_args()


def main():
    """Main script execution with CLI support."""
    args = parse_arguments()
    
    print("--- Daily Snyk Code Issues Check ---")
    
    # Use command line arguments, then environment variables, then prompt
    snyk_token = args.token or SNYK_TOKEN.strip()
    group_id = args.group_id or GROUP_ID.strip()

    if not snyk_token or not group_id:
        try:
            # Using getpass to securely hide the token input.
            if not snyk_token: snyk_token = getpass.getpass("🔑 Enter your Snyk API token: ").strip()
            if not group_id: group_id = input("🏢 Enter your Snyk Group ID: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nOperation cancelled. Exiting.")
            return
    else:
        print("✅ Using credentials from command line or environment variables.")

    if not snyk_token or not group_id:
        print("\n❌ Credentials could not be loaded. Exiting.")
        return
        
    headers = {'Authorization': f'token {snyk_token}', 'Accept': 'application/vnd.api+json'}

    # --- Phase 1: Token Validation ---
    if not validate_token(headers):
        return

    # --- Phase 2: Database Sync ---
    db_file = sanitize_filepath(args.db_file) if args.db_file else DB_FILE
    if args.db_file and not db_file:
        print("❌ Invalid database filename provided. Using default.")
        db_file = DB_FILE
    
    print(f"\nLoading local issue database from '{db_file}'...")
    last_updated_str, db_data = load_db_file(db_file)
    
    sync_needed = not args.no_sync
    if sync_needed and last_updated_str and not args.force_sync:
        last_updated_date = datetime.fromisoformat(last_updated_str).date()
        today_date_obj = datetime.now(timezone.utc).date()
        if last_updated_date == today_date_obj:
            if not args.quiet:
                answer = input("? Database was already updated today. Do you want to sync with Snyk again? (y/n) [n]: ").lower().strip()
                if answer != 'y':
                    sync_needed = False
                    print("  > Skipping Snyk API sync.")
            else:
                sync_needed = False
                print("  > Skipping Snyk API sync (already updated today).")
    
    if sync_needed:
        updated_db = update_database_from_snyk(headers, group_id, db_data)
        if updated_db is None:
            print("❌ Failed to sync with Snyk. Exiting.")
            return
        save_db_file(updated_db, db_file)
    else:
        updated_db = db_data

    # --- Phase 3: Report Generation ---
    try:
        if args.since:
            since_date_str = args.since
        else:
            today_date_str = datetime.now().strftime('%Y-%m-%d')
            if not args.quiet:
                prompt = f"\nEnter the start date to search for new SAST issues from (YYYY-MM-DD) [default: {today_date_str}]: "
                since_date_str = input(prompt).strip()
                if not since_date_str:
                    since_date_str = today_date_str
                    print(f"  > No date entered. Using default: {today_date_str}")
            else:
                since_date_str = today_date_str
                print(f"  > Using default date: {today_date_str}")
        
        report_start_date = datetime.strptime(since_date_str, '%Y-%m-%d').replace(tzinfo=timezone.utc)
    except (ValueError, KeyboardInterrupt, EOFError):
        print("\nInvalid date or operation cancelled. Exiting.")
        return

    report_issues = [
        issue for issue in updated_db 
        if datetime.fromisoformat(issue['created_at'].replace('Z', '+00:00')) >= report_start_date
    ]

    print(f"\n✨ Found {len(report_issues)} new issues created on or after {since_date_str}.")
    
    if report_issues:
        report_file = sanitize_filepath(args.report_file) if args.report_file else REPORT_FILE
        if args.report_file and not report_file:
            print("❌ Invalid report filename provided. Using default.")
            report_file = REPORT_FILE
        save_report_file(report_issues, report_file)


if __name__ == "__main__":
    main()