import os
import stat
import subprocess
import re
import shutil
import json
import time
import argparse
from typing import List, Dict, Any
from urllib.parse import urlparse, urlunparse
from tabulate import tabulate

REPOS = [
    {"url": "https://github.com/vignesh101/sybase_testing_1.git", "name": "sybase_testing_1"},
    {"url": "https://github.com/vignesh101/sybase_testing_2.git", "name": "sybase_testing_2"},
    {"url": "https://github.com/vignesh101/sybase_testing_3.git", "name": "sybase_testing_3"}
]

BASE_TARGET_DIR = "temp_repo"
JSON_OUTPUT_FILE = "sybase_usage_summary_report.json"
TABULAR_OUTPUT_FILE = "github_sybase_usage_detailed_report.txt"


def parse_arguments():
    parser = argparse.ArgumentParser(description='Scan repositories for Sybase usage.')
    parser.add_argument('access_token', help='GitHub access token')
    return parser.parse_args()


def on_rm_error(func, path, exc_info):
    """Error handler for shutil.rmtree."""
    # Check if the error is due to access permissions
    if not os.access(path, os.W_OK):
        # Try to change the permissions of the file
        os.chmod(path, stat.S_IWUSR)
        # Try the removal again
        func(path)
    else:
        raise


def remove_directory(directory: str) -> None:
    """Remove a directory and its contents if it exists."""
    if os.path.exists(directory):
        print(f"Removing existing directory: {directory}")
        max_attempts = 3
        for attempt in range(max_attempts):
            try:
                shutil.rmtree(directory, onerror=on_rm_error)
                break
            except Exception as e:
                print(f"Attempt {attempt + 1} failed to remove directory: {e}")
                if attempt < max_attempts - 1:
                    print("Retrying...")
                    time.sleep(1)  # Wait for 1 second before retrying
                else:
                    print(f"Failed to remove directory after {max_attempts} attempts.")
                    print("Please manually delete the directory and run the script again.")
                    return  # Instead of raising an exception, we'll just return and continue with the next repo


def clone_repo(repo_url: str, target_dir: str, token: str) -> bool:
    """Clone the given repository to the target directory using the provided token."""
    parsed_url = urlparse(repo_url)
    auth_url = urlunparse(parsed_url._replace(netloc=f"{token}@{parsed_url.netloc}"))

    remove_directory(target_dir)

    if os.path.exists(target_dir):
        print(f"Unable to remove existing directory: {target_dir}")
        return False

    try:
        subprocess.run(['git', 'clone', auth_url, target_dir],
                       check=True,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repository: {e}")
        print(f"Git output: {e.stderr.decode('utf-8')}")
        return False


def search_sybase_references(directory: str) -> List[Dict[str, Any]]:
    """Search for Sybase references in all files within the given directory, ignoring .git folder."""
    sybase_references = []
    sybase_patterns = [
        r'\bsybase\b',
        r'\bSybase\b',
        r'\bSYBASE\b',
        r'\bASE\b',
        r'\bAdaptive Server Enterprise\b',
        r'com\.sybase\.',
        r'net\.sourceforge\.jtds\.jdbc\.Driver',
        r'sybase\.jdbc\.SybDriver',
        r'com\.sybase\.jdbc[234]\.jdbc\.SybDriver',
        r'SYBASE_\w+',
        r"'sybase'",
        r'"sybase"',
        r'sybase://',
        r'@sybase',
        r'driver.*sybase',
        r'dialect.*sybase'
    ]

    for root, dirs, files in os.walk(directory):
        if '.git' in dirs:
            dirs.remove('.git')

        for file in files:
            file_path = os.path.join(root, file)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    for pattern in sybase_patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            line = content.splitlines()[line_num - 1]
                            sybase_references.append({
                                'file': os.path.relpath(file_path, directory),
                                'line_number': line_num,
                                'reference': match.group(),
                                'context': line.strip()
                            })
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")

    return sybase_references


def generate_repo_report(references: List[Dict[str, Any]], repo_name: str) -> Dict[str, Any]:
    """Generate a report for a single repository."""
    return {
        'repo_name': repo_name,
        'total_references': len(references),
        'references': references
    }


def generate_summary_report(repo_reports: List[Dict[str, Any]], json_output_file: str,
                            tabular_output_file: str) -> None:
    """Generate both JSON summary and tabular detailed reports for all repositories."""
    summary = {
        'total_repos_scanned': len(repo_reports),
        'repos_with_sybase_references': sum(1 for report in repo_reports if report['total_references'] > 0),
        'total_sybase_references': sum(report['total_references'] for report in repo_reports),
        'repo_summaries': repo_reports
    }

    # Generate JSON summary report
    with open(json_output_file, 'w') as f:
        json.dump(summary, f, indent=2)

    print(f"JSON summary report generated: {json_output_file}")

    # Generate tabular detailed report
    table_data = []
    for repo in repo_reports:
        for ref in repo['references']:
            table_data.append([
                repo['repo_name'],
                ref['file'],
                ref['line_number'],
                ref['reference'],
                ref['context']
            ])

    headers = ["Repository", "File", "Line Number", "Reference", "Context"]
    table = tabulate(table_data, headers=headers, tablefmt="grid")

    with open(tabular_output_file, 'w') as f:
        f.write("Github Sybase Usage Detailed Report\n")
        f.write("============================\n\n")
        f.write(table)

    print(f"Tabular detailed report generated: {tabular_output_file}")


def main():
    args = parse_arguments()
    ACCESS_TOKEN = args.access_token

    all_repo_reports = []

    for repo in REPOS:
        repo_name = repo['name']
        repo_url = repo['url']
        target_dir = os.path.join(BASE_TARGET_DIR, repo_name)

        try:
            print(f"\nProcessing repository: {repo_name}")
            print(f"Cloning repository: {repo_url}")
            if not clone_repo(repo_url, target_dir, ACCESS_TOKEN):
                print(f"Skipping {repo_name} due to cloning error.")
                continue

            print("Searching for Sybase references...")
            references = search_sybase_references(target_dir)

            repo_report = generate_repo_report(references, repo_name)
            all_repo_reports.append(repo_report)

            print(f"Sybase references found in {repo_name}: {len(references)}")

        except Exception as e:
            print(f"An error occurred while processing {repo_name}: {e}")
        finally:
            print(f"Cleaning up: Deleting cloned repository {repo_name}")
            remove_directory(target_dir)

    generate_summary_report(all_repo_reports, JSON_OUTPUT_FILE, TABULAR_OUTPUT_FILE)

    print(f"\nOverall Summary:")
    print(f"Total repositories scanned: {len(REPOS)}")
    print(
        f"Repositories with Sybase references: {sum(1 for report in all_repo_reports if report['total_references'] > 0)}")
    print(
        f"Total Sybase references found across all repos: {sum(report['total_references'] for report in all_repo_reports)}")
    print(f"JSON summary report saved to: {JSON_OUTPUT_FILE}")
    print(f"Tabular detailed report saved to: {TABULAR_OUTPUT_FILE}")


if __name__ == "__main__":
    main()
