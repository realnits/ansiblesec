pipeline {
    agent any
    
    environment {
        CARGO_HOME = "${WORKSPACE}/.cargo"
    }
    
    stages {
        stage('Build') {
            steps {
                sh '''
                    cargo build --release
                    cp target/release/ansiblesec ansiblesec
                '''
            }
        }
        
        stage('Security Scan') {
            steps {
                sh '''
                    ./ansiblesec scan . \
                        --format json \
                        --output security-report.json \
                        --ci-mode \
                        --threads 4
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'security-report.json', allowEmptyArchive: true
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'security-report.json',
                        reportName: 'Security Report'
                    ])
                }
            }
        }
        
        stage('Generate SBOM') {
            steps {
                sh '''
                    ./ansiblesec sbom . \
                        --format cyclonedx \
                        --output sbom.json \
                        --include-cve
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'sbom.json', allowEmptyArchive: true
                }
            }
        }
        
        stage('Lint') {
            steps {
                sh '''
                    ./ansiblesec lint . \
                        --format json \
                        --output lint-report.json
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'lint-report.json', allowEmptyArchive: true
                }
            }
        }
    }
    
    post {
        failure {
            emailext (
                subject: "Ansible Security Scan Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Security issues detected in ${env.JOB_NAME}. Check ${env.BUILD_URL} for details.",
                to: "${env.CHANGE_AUTHOR_EMAIL}"
            )
        }
    }
}
