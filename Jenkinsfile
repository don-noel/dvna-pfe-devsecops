pipeline {
    agent any

    environment {
        APP_URL = "http://localhost:9090"
    }

    stages {

        stage('1 - Secrets Scanning (Gitleaks)') {
            steps {
                echo '=== Scan des secrets hardcodes ==='
                bat '''
                    D:\\DevSecOps\\tools\\gitleaks\\gitleaks.exe detect --source . --config .gitleaks.toml -v
                '''
            }
        }

        stage('2 - SAST (Semgrep)') {
            steps {
                echo '=== Analyse statique du code ==='
                bat '''
                    docker run --rm -v "%CD%:/src" returntocorp/semgrep semgrep --config=p/nodejs --config=p/security-audit /src/server.js --error
                '''
            }
        }

        stage('3 - SCA (npm audit)') {
            steps {
                echo '=== Analyse des dependances ==='
                bat 'npm install'
                bat 'npm audit --audit-level=critical'
            }
        }

        stage('4 - Container Scan (Trivy)') {
            steps {
                echo '=== Scan de l image Docker ==='
                bat '''
                    docker build -t dvna-pfe:pipeline .
                    docker run --rm -v //var/run/docker.sock://var/run/docker.sock -v "%CD%:/workspace" -e TRIVY_IGNOREFILE=/workspace/.trivyignore ghcr.io/aquasecurity/trivy:latest image --severity HIGH,CRITICAL --exit-code 1 --ignore-unfixed dvna-pfe:pipeline
                '''
            }
        }

        stage('5 - IaC Security (Checkov)') {
            steps {
                echo '=== Analyse IaC Dockerfile ==='
                bat '''
                    docker run --rm -v "%CD%:/workspace" bridgecrew/checkov:2.3.0 -f /workspace/Dockerfile --framework dockerfile
                '''
            }
        }

        stage('6 - Run App for DAST') {
            steps {
                echo '=== Demarrage de l application pour ZAP ==='
                bat '''
                    docker rm -f dvna-pfe-app 2>nul || exit 0
                    docker network create zap-network 2>nul || exit 0
                    docker run -d --name dvna-pfe-app --network zap-network -p 9090:9090 dvna-pfe:pipeline
                '''
            }
        }

        stage('7 - DAST (OWASP ZAP)') {
            steps {
                echo '=== Test dynamique de l application ==='
                bat '''
                    if not exist zap-report mkdir zap-report
                    docker run --rm --network zap-network -v "%CD%\\zap-report:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://dvna-pfe-app:9090 -r zap-pipeline.html -I
                '''
            }
        }
    }

    post {
        always {
            echo '=== Pipeline DevSecOps termine ==='
            bat 'docker rm -f dvna-pfe-app 2>nul || exit 0'
            bat 'docker network rm zap-network 2>nul || exit 0'
        }
        success {
            echo '=== Tous les scans executes avec succes ==='
        }
        failure {
            echo '=== Des erreurs ont ete detectees ==='
        }
    }
}
