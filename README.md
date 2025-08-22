# Snyk Code Issues Reporter

A comprehensive security-focused toolkit for monitoring and analyzing Snyk Code issues in your organization.

## 🔒 Security Features

- **SSRF Protection**: All HTTP requests are validated against allowed Snyk API endpoints
- **Input Sanitization**: UUID and date inputs are properly validated and sanitized
- **Secure URL Building**: Safe URL construction prevents injection attacks
- **Environment Variable Support**: Secure credential management
- **Security Logging**: Comprehensive security event logging

## 📋 Scripts Overview

### 1. `Snykcodeissue.py` - Code Issues Reporter
Fetches current Snyk Code issues and compares them with previous runs to identify new issues.

**Features:**
- Fetches all open code issues for a specific date range
- Compares with previous reports to find new issues
- Generates detailed reports with issue metadata
- Command-line interface support

### 2. `daily_check.py` - Daily Issues Database Manager
Maintains a local database of Snyk Code issues and generates daily reports.

**Features:**
- Maintains persistent local database of issues
- Incremental sync with Snyk API
- Token validation
- Flexible report generation
- Command-line interface support

### 3. `security_config.py` - Security Configuration Module
Centralized security utilities and configuration management.

**Features:**
- URL validation for SSRF prevention
- Input sanitization utilities
- License compliance checking
- Security event logging

## 🚀 Quick Start

### Prerequisites

```bash
pip install -r requirements.txt
```

### Environment Variables

Set up your credentials securely:

```bash
export SNYK_TOKEN="your-snyk-api-token"
export SNYK_GROUP_ID="your-group-id"
```

### Basic Usage

#### Code Issues Reporter
```bash
# Interactive mode
python Snykcodeissue.py

# Command-line mode
python Snykcodeissue.py --token YOUR_TOKEN --group-id YOUR_GROUP_ID --since 2024-01-01

# Generate custom report
python Snykcodeissue.py --output custom_report.json --diff-output new_issues.json
```

#### Daily Database Manager
```bash
# Interactive mode
python daily_check.py

# Command-line mode
python daily_check.py --token YOUR_TOKEN --group-id YOUR_GROUP_ID --since 2024-01-01

# Automated mode (no prompts)
python daily_check.py --quiet --no-sync --since 2024-01-01
```

## 📖 Command-Line Reference

### Snykcodeissue.py Options

| Option | Short | Description |
|--------|-------|-------------|
| `--token` | `-t` | Snyk API token (overrides env var) |
| `--group-id` | `-g` | Snyk Group ID (overrides env var) |
| `--since` | `-s` | Start date for issue search (YYYY-MM-DD) |
| `--output` | `-o` | Output file for current report |
| `--diff-output` | `-d` | Output file for new issues diff |
| `--quiet` | `-q` | Suppress progress indicators |
| `--version` | `-v` | Show version information |
| `--help` | `-h` | Show help message |

### daily_check.py Options

| Option | Short | Description |
|--------|-------|-------------|
| `--token` | `-t` | Snyk API token (overrides env var) |
| `--group-id` | `-g` | Snyk Group ID (overrides env var) |
| `--since` | `-s` | Start date for report generation (YYYY-MM-DD) |
| `--db-file` | | Database file path |
| `--report-file` | `-r` | Report output file |
| `--no-sync` | | Skip database sync with Snyk API |
| `--force-sync` | | Force sync even if updated today |
| `--quiet` | `-q` | Suppress progress indicators |
| `--version` | `-v` | Show version information |
| `--help` | `-h` | Show help message |

## 📁 Output Files

- `snyk_report_previous.json` - Current issues baseline (Snykcodeissue.py)
- `snyk_report_new_diff.json` - New issues since last run (Snykcodeissue.py)
- `snyk_code_issues_db.json` - Local issues database (daily_check.py)
- `daily_snyk_code_issues_report.json` - Daily report (daily_check.py)

## 🛠️ Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `SNYK_TOKEN` or `TOKEN` | Your Snyk API token | Yes |
| `SNYK_GROUP_ID` or `GROUP_ID` | Your Snyk Group ID | Yes |
| `SNYK_API_URL` | Snyk API URL (default: https://api.snyk.io) | No |

### Security Configuration

The scripts include comprehensive security measures:

1. **URL Validation**: Only allows HTTPS connections to `api.snyk.io`
2. **Input Sanitization**: All user inputs are validated before use
3. **Safe Error Handling**: No sensitive information leaked in errors
4. **Security Logging**: All security events are logged

## 🔍 Security Scanning

The codebase has been scanned and secured against:

- ✅ Server-Side Request Forgery (SSRF)
- ✅ Input injection attacks
- ✅ URL manipulation attacks
- ✅ Information disclosure

Run security scans regularly:

```bash
# Snyk code scan
snyk code test

# Dependency scan
snyk test

# Container scan (if applicable)
snyk container test <image>
```

## 📊 Report Structure

### Issue Report Format

```json
{
  "issue_id": "uuid",
  "organization_id": "uuid",
  "project_id": "uuid",
  "organization_name": "string",
  "project_name": "string",
  "issue_title": "string",
  "severity": "HIGH|MEDIUM|LOW",
  "created_at": "ISO-8601 timestamp",
  "file_location": "path/to/file",
  "issue_url": "https://app.snyk.io/...",
  "details": {...}
}
```

## 🚨 Troubleshooting

### Common Issues

1. **Authentication Errors**
   - Verify your `SNYK_TOKEN` is correct and not expired
   - Check that you have access to the specified `GROUP_ID`

2. **Network Errors**
   - Ensure you have internet connectivity
   - Check if your network allows HTTPS connections to `api.snyk.io`

3. **Permission Errors**
   - Verify your token has the necessary permissions for the group
   - Check file write permissions for output files

4. **Rate Limiting**
   - The scripts include automatic retry logic
   - If you encounter rate limits, try running with longer intervals

### Debug Mode

For debugging, you can modify the scripts to include more verbose logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Run security scans on your changes
4. Submit a pull request

### Security Guidelines

- All user inputs must be validated
- Use the provided security utilities
- Never log sensitive information
- Follow the established security patterns

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🔒 Security

For security issues, please see [SECURITY.md](SECURITY.md) for reporting guidelines.

## 📞 Support

For issues and questions:

1. Check the troubleshooting section
2. Review the command-line help: `python script.py --help`
3. Check existing issues in the repository
4. Create a new issue with detailed information

---
