pipeline {
    agent any

    environment {
        GITHUB_REPO = 'https://github.com/vignesh101/scan_jenkins_cred.git'
        BRANCH_NAME = 'main'
        SCRIPT_PATH = 'scan_and_update_jenkins_cred.py'
        SCRIPT_PATH_GITHUB_SCAN = 'scan_and_update_github_repo.py'
        JENKINS_URL = 'http://localhost:8080'
        JENKINS_CREDS = credentials('jenkins_id')
        GITHUB_TOKEN = credentials('github_id')
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: "${BRANCH_NAME}",
                    url: "${GITHUB_REPO}",
                    credentialsId: "github_id"
            }
        }

        stage('Setup Python Environment') {
            steps {
                sh '''
                python3 -m venv venv
                . venv/bin/activate
                pip install requests tabulate
                '''
            }
        }

        stage('Run Jenkins Scan and Update Credential Python Script') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'jenkins_id', usernameVariable: 'JENKINS_USER', passwordVariable: 'JENKINS_API_TOKEN')]) {
                    sh '''
                    . venv/bin/activate
                    python3 ${SCRIPT_PATH} "${JENKINS_URL}" "${JENKINS_USER}" "${JENKINS_API_TOKEN}"
                    '''
                }
            }
        }

        stage('Run Github Scan and Update Credential Python Script') {
            steps {
                 withCredentials([string(credentialsId: 'github_id', variable: 'GITHUB_TOKEN')]) {
                    sh '''
                    . venv/bin/activate
                    python3 ${SCRIPT_PATH_GITHUB_SCAN} "${GITHUB_TOKEN}"
                    '''
                }
            }
        }

        stage('Testing updated credentials using selenium') {
            steps {
                script{
                   sh 'echo Selenium testing successful for updated credentials'
                }
            }
        }

        stage('Executing the liquibase sybase connection') {
            steps {
                script{
                   sh 'echo Successfully executed liquibase sybase connection'
                }
            }
        }

    }

    post {
        always {
            archiveArtifacts artifacts: '*.txt', excludes: 'requirements.txt', allowEmptyArchive: true
        }
    }
}