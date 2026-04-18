import groovy.json.JsonOutput

pipeline {
    agent any

    environment {
        APP_URL   = "http://localhost:9090"
        DASHBOARD = "http://localhost:3500/api/report"
    }

    stages {

        stage('1 - Secrets Scanning (Gitleaks)') {
            steps {
                echo '=== Scan des secrets hardcodes ==='
                script {
                    bat '''
                        if not exist gitleaks-report mkdir gitleaks-report
                        D:\\DevSecOps\\tools\\gitleaks\\gitleaks.exe detect --source . --config .gitleaks.toml --no-git --no-banner -v > gitleaks-report\\gitleaks-report.txt 2>&1 || exit 0
                    '''
                    def content = powershell(encoding: 'UTF-8', returnStdout: true, script: '''
                        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
                        $content = Get-Content -Path "gitleaks-report/gitleaks-report.txt" -Encoding UTF8 -Raw
                        Write-Output $content
                    ''').trim()
                    def status = content.contains('leaks found') && !content.contains('leaks found: 0') ? 'warning' : 'success'
                    sendToDashboard("Gitleaks", content, status)
                    if (status == 'warning') {
                        error("Gitleaks a detecte des secrets — pipeline bloque !")
                    }
                }
            }
        }

        stage('2 - SAST (Semgrep)') {
            steps {
                echo '=== Analyse statique du code ==='
                script {
                    bat '''
                        chcp 65001
                        if not exist semgrep-report mkdir semgrep-report
                        docker run --rm -v "%CD%:/src" -e SEMGREP_FORCE_COLOR=0 -e NO_COLOR=1 -e PYTHONIOENCODING=utf-8 -e PYTHONUTF8=1 semgrep/semgrep semgrep --config=p/nodejs --config=p/security-audit --text /src/server.js --output /src/semgrep-report/semgrep-report.txt 2>nul || exit 0
                    '''
                    def content = powershell(encoding: 'UTF-8', returnStdout: true, script: '''
                        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
                        $content = Get-Content -Path "semgrep-report/semgrep-report.txt" -Encoding UTF8 -Raw
                        Write-Output $content
                    ''').trim()
                    def status = (content.contains('findings') || content.contains('Code Findings') || content.contains('▶')) ? 'warning' : 'success'
                    sendToDashboard("Semgrep", content, status)
                    if (status == 'warning') {
                        error("Semgrep a detecte des vulnerabilites — pipeline bloque !")
                    }
                }
            }
        }

        stage('3 - SCA (npm audit)') {
            steps {
                echo '=== Analyse des dependances ==='
                script {
                    bat '''
                        if not exist sca-report mkdir sca-report
                        npm audit --audit-level=critical > sca-report\\npm-audit-report.txt 2>&1 || exit 0
                    '''
                    def content = powershell(encoding: 'UTF-8', returnStdout: true, script: '''
                        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
                        $content = Get-Content -Path "sca-report/npm-audit-report.txt" -Encoding UTF8 -Raw
                        Write-Output $content
                    ''').trim()
                    def status = content.contains('critical') || content.contains('high') ? 'warning' : 'success'
                    sendToDashboard("npm audit", content, status)
                    if (status == 'warning') {
                        error("npm audit a detecte des vulnerabilites critiques — pipeline bloque !")
                    }
                }
            }
        }

        stage('4 - Container Scan (Trivy)') {
            steps {
                echo '=== Scan de l image Docker ==='
                script {
                    bat '''
                        docker build -t dvna-pfe:pipeline .
                        if not exist trivy-report mkdir trivy-report
                        docker run --rm -v //var/run/docker.sock://var/run/docker.sock -v "%CD%/trivy-report:/report" ghcr.io/aquasecurity/trivy:latest image --severity HIGH,CRITICAL --format table --no-progress --ignore-unfixed --skip-dirs /usr/local/lib/node_modules --skip-dirs /opt --output /report/trivy-report.txt dvna-pfe:pipeline 2>nul || exit 0
                    '''
                    def content = powershell(encoding: 'UTF-8', returnStdout: true, script: '''
                        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
                        $content = Get-Content -Path "trivy-report/trivy-report.txt" -Encoding UTF8 -Raw
                        Write-Output $content
                    ''').trim()
                    def status = content.contains('CRITICAL') || content.contains('HIGH') ? 'warning' : 'success'
                    sendToDashboard("Trivy", content, status)
                    if (status == 'warning') {
                        error("Trivy a detecte des vulnerabilites HIGH/CRITICAL — pipeline bloque !")
                    }
                }
            }
        }

        stage('5 - IaC Security (Checkov)') {
            steps {
                echo '=== Analyse IaC Dockerfile ==='
                script {
                    bat '''
                        if not exist checkov-report mkdir checkov-report
                        docker run --rm -v "%CD%:/workspace" bridgecrew/checkov:2.3.0 -f /workspace/Dockerfile --framework dockerfile > checkov-report\\checkov-report.txt 2>&1 || exit 0
                    '''
                    def content = powershell(encoding: 'UTF-8', returnStdout: true, script: '''
                        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
                        $content = Get-Content -Path "checkov-report/checkov-report.txt" -Encoding UTF8 -Raw
                        Write-Output $content
                    ''').trim()
                    def status = content.contains('Failed checks') && !content.contains('Failed checks: 0') ? 'warning' : 'success'
                    sendToDashboard("Checkov", content, status)
                    if (status == 'warning') {
                        error("Checkov a detecte des problemes IaC — pipeline bloque !")
                    }
                }
            }
        }

        stage('6 - Run App for DAST') {
            steps {
                echo '=== Demarrage de l application pour ZAP ==='
                bat '''
                    docker rm -f dvna-pfe-app 2>nul || exit 0
                    docker run -d --name dvna-pfe-app -p 9090:9090 dvna-pfe:pipeline
                '''
            }
        }

        stage('7 - DAST (OWASP ZAP)') {
            steps {
                echo '=== Test dynamique de l application ==='
                script {
                    bat '''
                        if not exist zap-report mkdir zap-report
                        docker run --rm --add-host=host.docker.internal:host-gateway -v "%CD%\\zap-report:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:9090 -r zap-pipeline.html -I > zap-report\\zap-console-report.txt 2>&1 || exit 0
                    '''
                    def content = powershell(encoding: 'UTF-8', returnStdout: true, script: '''
                        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
                        $content = Get-Content -Path "zap-report/zap-console-report.txt" -Encoding UTF8 -Raw
                        Write-Output $content
                    ''').trim()
                    def status = content.contains('WARN-NEW') ? 'warning' : 'success'
                    sendToDashboard("OWASP ZAP", content, status)
                    if (status == 'warning') {
                        error("OWASP ZAP a detecte des vulnerabilites — pipeline bloque !")
                    }
                }
            }
        }
    }

    post {
        always {
            echo '=== Pipeline DevSecOps termine ==='
            script {
                def finalStatus = currentBuild.result == 'SUCCESS' ? 'success' : 'warning'
                sendToDashboard("Pipeline Summary", "Pipeline termine - Build ${BUILD_NUMBER}", finalStatus)
            }
            bat 'docker rm -f dvna-pfe-app 2>nul || exit 0'
        }
        success {
            echo '=== Tous les scans executes avec succes ==='
        }
        failure {
            echo '=== Des erreurs ont ete detectees ==='
        }
    }
}

def sendToDashboard(String tool, String content, String status) {
    try {
        def jsonStr = JsonOutput.toJson([
            tool   : tool,
            build  : env.BUILD_NUMBER,
            branch : env.BRANCH ?: 'master',
            content: content,
            status : status
        ])
        def jsonFile = "report_${tool.replaceAll('[^a-zA-Z0-9]', '_')}.json"
        writeFile file: jsonFile, text: jsonStr, encoding: 'UTF-8'
        bat """
            curl -s -X POST %DASHBOARD% ^
            -H "Content-Type: application/json; charset=utf-8" ^
            --data-binary @${jsonFile} ^
            > nul 2>&1 || exit 0
        """
        bat "@del ${jsonFile} > nul 2>&1 || exit 0"
    } catch(e) {
        echo "Envoi dashboard echoue pour ${tool}: ${e.message}"
    }
}
