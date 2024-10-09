import requests
import json
import xml.etree.ElementTree as ET
from requests.auth import HTTPBasicAuth
import re
from typing import Dict, List, Any, Tuple
from tabulate import tabulate
import argparse

# Jenkins configuration will be set from command line arguments
JENKINS_URL = ""
JENKINS_USER = ""
JENKINS_API_TOKEN = ""

JSON_OUTPUT_FILE = "jenkins_sybase_credentials_report.json"
TABULAR_OUTPUT_FILE = "jenkins_sybase_credentials_report.txt"
UPDATED_CREDS_OUTPUT_FILE = "jenkins_updated_credentials_report.txt"


def parse_arguments():
    global JENKINS_URL, JENKINS_USER, JENKINS_API_TOKEN
    parser = argparse.ArgumentParser(description='Process Jenkins credentials.')
    parser.add_argument('jenkins_url', help='Jenkins URL')
    parser.add_argument('username', help='Jenkins username')
    parser.add_argument('password', help='Jenkins password or API token')
    args = parser.parse_args()

    JENKINS_URL = args.jenkins_url
    JENKINS_USER = args.username
    JENKINS_API_TOKEN = args.password


def get_jenkins_data(url: str) -> Any:
    response = requests.get(url, auth=HTTPBasicAuth(JENKINS_USER, JENKINS_API_TOKEN))
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Failed to fetch data from {url}")
        return None


def get_job_config(job_url: str) -> str:
    config_url = f"{job_url}config.xml"
    response = requests.get(config_url, auth=HTTPBasicAuth(JENKINS_USER, JENKINS_API_TOKEN))
    if response.status_code == 200:
        return response.text
    else:
        print(f"Failed to fetch config for {job_url}")
        return ""


def parse_job_config(config_xml: str) -> List[str]:
    root = ET.fromstring(config_xml)
    sybase_credentials = []

    # Check for credentials in traditional Jenkins jobs
    for binding in root.findall(".//org.jenkinsci.plugins.credentialsbinding.impl.SecretBuildWrapper/bindings/*"):
        credential_id = binding.find("credentialsId")
        if credential_id is not None and "sybase" in credential_id.text.lower():
            sybase_credentials.append(credential_id.text)

    # Check for credentials in pipeline scripts
    script_elements = root.findall(".//script") + root.findall(".//scriptPath")
    for script_element in script_elements:
        if script_element.text:
            cred_ids = re.findall(r"credentialsId:\s*'([^']*sybase[^']*)'", script_element.text, re.IGNORECASE)
            sybase_credentials.extend(cred_ids)

    return list(set(sybase_credentials))  # Remove duplicates


def scan_for_sybase_credentials(item: Dict[str, Any], path: str, report_data: Dict[str, Tuple[str, List[str]]]):
    current_path = f"{path}/{item['name']}" if path else item['name']
    if item['_class'] == 'com.cloudbees.hudson.plugins.folder.Folder':
        jobs_url = f"{item['url']}api/json?tree=jobs[name,url,_class]"
        jobs_data = get_jenkins_data(jobs_url)
        if jobs_data and 'jobs' in jobs_data:
            for job in jobs_data['jobs']:
                scan_for_sybase_credentials(job, current_path, report_data)
    elif item['_class'] in ['org.jenkinsci.plugins.workflow.job.WorkflowJob', 'hudson.model.FreeStyleProject']:
        config_xml = get_job_config(item['url'])
        sybase_credentials = parse_job_config(config_xml)
        if sybase_credentials:
            report_data[item['name']] = (current_path, sybase_credentials)


def generate_json_report(report_data: Dict[str, Tuple[str, List[str]]]) -> str:
    return json.dumps(report_data, indent=2)


def generate_tabular_report(report_data: Dict[str, Tuple[str, List[str]]]) -> str:
    table_data = []
    for job_name, (job_path, credential_ids) in report_data.items():
        for cred_id in credential_ids:
            table_data.append([job_name, job_path, cred_id])

    headers = ["Job Name", "Job Path", "Credential ID"]
    return tabulate(table_data, headers=headers, tablefmt="grid")


def extract_json_from_result(result: str) -> str:
    """Extract the JSON part from the mixed string-and-JSON output."""
    json_match = re.search(r'\[.*\]', result, re.DOTALL)
    if json_match:
        return json_match.group()
    return ""


def generate_updated_creds_report(updated_creds: List[Dict[str, Any]]) -> str:
    table_data = []
    for cred in updated_creds:
        table_data.append([cred['job'], cred['id'], cred['username'], cred['password']])

    headers = ["Job Path", "Old Credential ID", "New Username", "New Password"]
    return tabulate(table_data, headers=headers, tablefmt="grid")


def run_groovy_script(script: str) -> str:
    url = f"{JENKINS_URL}/scriptText"
    data = {
        'script': script
    }
    response = requests.post(url, auth=HTTPBasicAuth(JENKINS_USER, JENKINS_API_TOKEN), data=data)
    if response.status_code == 200:
        return response.text
    else:
        print(f"Failed to run Groovy script. Status code: {response.status_code}")
        print(f"Response content: {response.text}")
        return ""


def main():
    parse_arguments()
    report_data = {}
    root_url = f"{JENKINS_URL}/api/json?tree=jobs[name,url,_class]"
    root_data = get_jenkins_data(root_url)
    if root_data and 'jobs' in root_data:
        for item in root_data['jobs']:
            scan_for_sybase_credentials(item, "", report_data)

    # Generate and save JSON report
    json_report = generate_json_report(report_data)
    with open(JSON_OUTPUT_FILE, 'w') as f:
        f.write(json_report)
    print(f"JSON report saved to: {JSON_OUTPUT_FILE}")

    # Generate and save tabular report
    tabular_report = generate_tabular_report(report_data)
    with open(TABULAR_OUTPUT_FILE, 'w') as f:
        f.write("Jenkins Jobs Using Sybase Credentials:\n")
        f.write("======================================\n\n")
        f.write(tabular_report)
    print(f"Tabular report saved to: {TABULAR_OUTPUT_FILE}")

    # Print summary
    print("\nSummary:")
    print(f"Total jobs with Sybase credentials: {len(report_data)}")
    print(f"Total Sybase credentials found: {sum(len(creds) for _, creds in report_data.values())}")

    # Groovy script template
    groovy_script_template = """
    import jenkins.model.Jenkins
    import com.cloudbees.plugins.credentials.CredentialsProvider
    import com.cloudbees.plugins.credentials.domains.Domain
    import com.cloudbees.plugins.credentials.impl.UsernamePasswordCredentialsImpl
    import com.cloudbees.plugins.credentials.CredentialsScope
    import hudson.util.Secret
    import java.util.UUID
    import groovy.json.JsonSlurper
    import groovy.json.JsonOutput

    def updateCredential(cred) {
        def newUsername = "oracleUser_" + UUID.randomUUID().toString().substring(0, 8)
        def newPassword = UUID.randomUUID().toString()

        def updatedCred = new UsernamePasswordCredentialsImpl(
            CredentialsScope.GLOBAL,
            cred.id,
            cred.description.replace("Sybase", "Oracle"),
            newUsername,
            newPassword
        )

        return [updatedCred: updatedCred, newUsername: newUsername, newPassword: newPassword]
    }

    def getJobByFullName(fullName) {
        return Jenkins.instance.getItemByFullName(fullName)
    }

    def updateCredentialsForJob(jobFullName, credentialIds) {
        def job = getJobByFullName(jobFullName)
        def updatedCredentials = []

        if (job == null) {
            println "Job not found: ${jobFullName}"
            return updatedCredentials
        }

        credentialIds.each { credId ->
            def cred = CredentialsProvider.lookupCredentials(
                UsernamePasswordCredentialsImpl.class,
                job,
                null,
                null
            ).find { it.id == credId }

            if (cred) {
                try {
                    def updatedResult = updateCredential(cred)
                    def updatedCred = updatedResult.updatedCred
                    def newUsername = updatedResult.newUsername
                    def newPassword = updatedResult.newPassword

                    CredentialsProvider.lookupStores(job).each { store ->
                        if (store.updateCredentials(Domain.global(), cred, updatedCred)) {
                            updatedCredentials << [
                                id: cred.id,
                                username: newUsername,
                                password: newPassword,
                                job: jobFullName
                            ]
                            println "Updated credential: ${cred.id} in job: ${jobFullName}"
                            return true  // Exit the each loop after successful update
                        }
                    }
                } catch (Exception e) {
                    println "Failed to update credential: ${cred.id} in job: ${jobFullName}. Error: ${e.message}"
                }
            } else {
                println "No credential found with ID: ${credId} for job: ${jobFullName}"
            }
        }

        return updatedCredentials
    }

    def jsonSlurper = new JsonSlurper()
    def input = jsonSlurper.parseText('''${json}''')
    def allUpdatedCreds = []

    input.each { jobName, data ->
        def (jobPath, credentialIds) = data
        def updatedCreds = updateCredentialsForJob(jobPath, credentialIds)
        allUpdatedCreds.addAll(updatedCreds)
    }

    return JsonOutput.toJson(allUpdatedCreds)
    """

    # Properly escape the JSON string
    escaped_report_json = json.dumps(report_data).replace("'", "\\'").replace('"', '\\"')

    # Construct the Groovy script by embedding the escaped JSON
    groovy_script = groovy_script_template.replace("${json}", escaped_report_json)

    # Run Groovy script to update credentials
    result = run_groovy_script(groovy_script)
    print("\nUpdate Result:")
    print(result)

    # Parse the update result and generate a tabular report
    try:
        json_str = extract_json_from_result(result)
        updated_creds = json.loads(json_str)
        updated_creds_report = generate_updated_creds_report(updated_creds)
        with open(UPDATED_CREDS_OUTPUT_FILE, 'w') as f:
            f.write("Updated Sybase Credentials:\n")
            f.write("===========================\n\n")
            f.write(updated_creds_report)
        print(f"Updated credentials report saved to: {UPDATED_CREDS_OUTPUT_FILE}")
    except json.JSONDecodeError as e:
        print(f"Failed to parse update result: {e}")
        print("No updated credentials report generated.")
    except Exception as e:
        print(f"An error occurred while generating the updated credentials report: {e}")


if __name__ == "__main__":
    main()
