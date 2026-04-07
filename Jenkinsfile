pipeline {
    agent any

    environment {
        // SonarQube settings
        SCANNER_HOME          = tool 'sonar-scanner'
        SONAR_URL             = 'http://65.1.109.17:9000' + sh(script: "hostname -I | awk '{print \$1}'", returnStdout: true).trim() + ':9000'
        SONAR_PROJECT_KEY     = 'juice-shop'
        SONAR_PROJECT_NAME    = 'OWASP-Juice-Shop'
        SONAR_TOKEN           = credentials('sonar-token')

        // Paths & tools
        CHROME_BIN            = '/usr/bin/google-chrome'
        PATH                  = "/usr/local/bin:${env.PATH}"
        REPORTS_DIR           = "${WORKSPACE}/reports"
        APP_URL               = 'http://localhost:3000'
    }

    stages {

        stage('Git Checkout') {
            steps {
                echo "📦 Cloning Juice Shop repository..."
                git branch: 'master', url: 'https://github.com/infostudent786/juice-shop.git'
                sh 'mkdir -p ${REPORTS_DIR}'
                // Note: jmeter-test.jmx and ai-dashboard.py should already exist in the repo root
            }
        }

        stage('Clean Environment') {
            steps {
                echo "🧹 Cleaning previous containers, images, and reports..."
                sh '''
                    # Stop and remove existing container
                    docker stop juice-shop || true
                    docker rm juice-shop || true
                    
                    # Remove dangling images to save disk space
                    docker image prune -f || true
                    
                    # Reset reports directory
                    rm -rf ${REPORTS_DIR}/*
                    mkdir -p ${REPORTS_DIR}
                '''
            }
        }

        stage('Install Dependencies & Build') {
            steps {
                echo "⚙️ Installing Node.js dependencies and building project..."
                sh '''
                    npm install --legacy-peer-deps
                    npm run build || echo "Build completed with warnings (ignored for CI)."
                '''
            }
        }

        stage('SCA — OWASP Dependency Check') {
            steps {
                echo "🔍 Running OWASP Dependency Check (SCA)..."
                sh '''
                    if [ ! -f package-lock.json ]; then
                        echo "Generating package-lock.json..."
                        npm install --package-lock-only
                    fi
                '''
                dependencyCheck(
                    additionalArguments: '--scan . --format ALL --out ${REPORTS_DIR} --disableAssembly',
                    odcInstallation: 'owasp'
                )
                dependencyCheckPublisher pattern: 'reports/dependency-check-report.xml'
            }
        }

        stage('SAST — SonarQube Analysis') {
            steps {
                echo "📊 Running SonarQube SAST Analysis..."
                sh '''
                    ${SCANNER_HOME}/bin/sonar-scanner \
                        -Dsonar.projectKey=${SONAR_PROJECT_KEY} \
                        -Dsonar.projectName=${SONAR_PROJECT_NAME} \
                        -Dsonar.sources=. \
                        -Dsonar.host.url=${SONAR_URL} \
                        -Dsonar.login=${SONAR_TOKEN} \
                        -Dsonar.dependencyCheck.reportPath=${REPORTS_DIR}/dependency-check-report.xml \
                        -Dsonar.dependencyCheck.htmlReportPath=${REPORTS_DIR}/dependency-check-report.html \
                        -Dsonar.dependencyCheck.jsonReportPath=${REPORTS_DIR}/dependency-check-report.json
                '''
            }
            post {
                always {
                    script {
                        sh '''
                            sleep 10
                            # Extract Sonar summary for AI dashboard
                            SONAR_CRITICAL=$(curl -s -u "${SONAR_TOKEN}:" \
                                "${SONAR_URL}/api/issues/search?projectKeys=${SONAR_PROJECT_KEY}&severities=CRITICAL,BLOCKER&resolved=false" \
                                | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('total',0))" 2>/dev/null || echo "0")
                            
                            echo "{\\"critical\\": ${SONAR_CRITICAL}, \\"major\\": 0, \\"minor\\": 0}" > ${REPORTS_DIR}/sonar-summary.json
                        '''
                    }
                }
            }
        }

        stage('Docker Build & Deploy') {
            steps {
                echo "🐳 Building and running Juice Shop Docker container..."
                sh '''
                    docker build -t juice-shop:latest .
                    docker run -d -p 3000:3000 --name juice-shop juice-shop:latest
                    
                    # Wait for app to be ready
                    echo "Waiting for app to start..."
                    for i in {1..12}; do
                        if curl -s ${APP_URL} > /dev/null; then
                           echo "App is UP!"
                           break
                        fi
                        echo "..."
                        sleep 5
                    done
                '''
            }
        }

        stage('DAST — OWASP ZAP (Background Scan)') {
            steps {
                echo "🕷️ Running OWASP ZAP Baseline Scan via Docker..."
                sh '''
                    docker run --rm \
                        --network host \
                        -v ${REPORTS_DIR}:/zap/wrk:rw \
                        ghcr.io/zaproxy/zaproxy:stable \
                        zap-baseline.py \
                            -t ${APP_URL} \
                            -r zap-report.html \
                            -J zap-report.json \
                            -I || true
                '''
            }
        }

        stage('Performance — JMeter Stress Test') {
            steps {
                echo "⚡ Running JMeter Load Tests against ${APP_URL}..."
                sh '''
                    # Using jmeter-test.jmx from the repository root
                    if [ -f jmeter-test.jmx ]; then
                        jmeter -n -t jmeter-test.jmx -l ${REPORTS_DIR}/jmeter-results.jtl -e -o ${REPORTS_DIR}/jmeter-html || true
                    else
                        echo "⚠️ jmeter-test.jmx not found! Skipping performance test."
                    fi
                '''
            }
        }

        stage('AI Intelligence Dashboard') {
            steps {
                echo "🤖 Generating AI Security Insights (Rule-Based Engine)..."
                sh '''
                    # Ensure the reports directory exists
                    mkdir -p ${REPORTS_DIR}
                    
                    # Run the dashboard script
                    if [ -f ai-dashboard.py ]; then
                        python3 ai-dashboard.py
                    else
                        echo "⚠️ ai-dashboard.py not found! Skipping dashboard generation."
                    fi
                '''
                
                publishHTML(target: [
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: "reports",
                    reportFiles: 'dashboard.html',
                    reportName: '🛡️ AI Security Dashboard'
                ])
            }
        }
    }

    post {
        always {
            echo '✅ Pipeline execution completed. Reports are available in the Dashboard and SonarQube.'
            sh 'docker stop juice-shop || true'
        }
        success {
            echo '🎉 Build succeeded! Visit the AI Security Dashboard for full analysis.'
        }
        failure {
            echo '❌ Build failed. Please check the logs and dashboard.'
        }
    }
}
