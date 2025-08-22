# Snyk Code Issues Reporter & Comparison Tool

> A Python script to automatically fetch new Snyk Code issues, compare them against a previous run, and generate a report of truly new vulnerabilities.

This tool helps streamline vulnerability management by automating the process of identifying newly introduced code issues since the last scan, complete with detailed descriptions and remediation advice.

---

## ⚙️ How It Works

The script operates on an automated baseline comparison workflow:

1.  **Initial Run (Building the Database)**: The first time the script is executed, it fetches all open Snyk Code issues from your Group that were created after the start date you provide. It then saves this complete list as a baseline snapshot (your issue DB) in a file named **`snyk_report_previous.json`**.

    > **Note on the Start Date:** On the very first run, this date determines how far back the script will look to build your initial issue database. For a more complete history, you can enter an older date like `2020-01-01`.

2.  **Subsequent Runs (Comparing for New Issues)**: On every run after the first, the script:
    * Fetches the most current list of open issues from Snyk.
    * Compares this new list against the issues stored in **`snyk_report_previous.json`**.
    * Identifies any issues that exist in the new list but not in the previous one.
    * Saves these "truly new" issues into a separate report named **`snyk_report_new_diff.json`**.
    * Finally, it overwrites **`snyk_report_previous.json`** with the current list, updating the baseline for the next comparison.

---

## 🔌 APIs Used

This tool is built using the Snyk REST API. The following endpoints are used to gather the necessary data:

* **`GET /rest/groups/{group_id}/orgs`**: To discover all organizations within the specified Snyk Group.
* **`GET /rest/orgs/{org_id}/projects`**: To list all projects within each discovered organization. This is used to map issue data back to human-readable project names.
* **`GET /rest/groups/{group_id}/issues`**: The primary endpoint for fetching the list of all open code issues across the entire Group.
* **`GET /rest/orgs/{org_id}/issues/{issue_id}`**: Called for each individual issue to fetch rich details, including its full description, remediation advice, and data flows.

---

## 🚀 How to Use

### Prerequisites

* Python 3
* A Snyk account with an **API Token** and a **Group ID**.

### Step 1: Save the Script

Copy the complete Python script from the **"Full Python Script"** section below and save it into a file named **`snyk_code_reporter.py`**.

### Step 2: Install Dependencies

Open your terminal in the same directory where you saved the script and install the required Python libraries.

```shell
pip3 install requests python-dateutil# Snyk-Code-API-


# Daily Snyk Code Issues Check

> A Python script that maintains a local database of Snyk Code issues and generates reports on new vulnerabilities discovered since a specific date.

This tool provides a persistent and efficient way to monitor Snyk Code findings. It syncs with the Snyk API to keep a local JSON database up-to-date and then allows you to query that database for issues created after a date you specify.

---

## ⚙️ How It Works

The script operates in three main phases on every run:

1.  **Credential Validation (Two-Step)**:
    * **Token Check**: It first makes a call to the Snyk API (`/v1/user/me`) to verify that the provided **API Token is valid** and active.
    * **Group Check**: If the token is valid, it then makes a second call (`/rest/groups`) to verify that the token has permission to access the specified **Group ID**. If the ID is wrong, it will list the correct ones available to you.

2.  **Database Synchronization**:
    * If credentials are valid, the script loads its local issue database, **`snyk_code_issues_db.json`**.
    * **Conditional Sync**: If the database was already updated today, the script will ask if you want to sync again.
    * **Efficient Fetching**: If syncing proceeds, it efficiently asks the Snyk API only for issues created *after* the most recently found issue.

3.  **Report Generation**:
    * After the database is synced, the script prompts for a date to search for new SAST issues from (defaults to today).
    * **Conditional Reporting**: If new issues are found, the results are saved to **`daily_snyk_code_issues_report.json`**. If zero new issues are found, no report file is created.

---

## 🚀 How to Use

### Step 1: Set Environment Variables (Recommended)

For the most secure and convenient setup, set your Snyk credentials as environment variables. On macOS or Linux, add these lines to your `~/.zshrc` or `~/.bash_profile`.

```shell
export SNYK_TOKEN="your-snyk-api-token-goes-here"
export SNYK_GROUP_ID="your-snyk-group-id-goes-here"
# Optional: Set for non-US regions (e.g., [https://api.eu.snyk.io](https://api.eu.snyk.io))
# export SNYK_API_URL="your-region-specific-api-url"
