pipeline {
    agent any
    options { timestamps(); disableConcurrentBuilds() }
    environment { IMAGE_NAME = 'fastapi-security-lab' }
    stages {
        stage('Install') {
            steps {
                sh '''
                    python3 -m venv .venv
                    .venv/bin/python -m pip install -r requirements.txt -r requirements-dev.txt
                '''
            }
        }
        stage('Lint') { steps { sh '.venv/bin/ruff check app tests' } }
        stage('Test') {
            steps {
                withCredentials([string(credentialsId: 'fastapi-ci-jwt-secret', variable: 'JWT_SECRET')]) {
                    sh '''
                        export DB_PATH="$WORKSPACE/jenkins-security-test.sqlite3"
                        rm -f "$DB_PATH" "$DB_PATH-wal" "$DB_PATH-shm"
                        .venv/bin/python -m pytest -q --cov=app --cov-report=xml --junitxml=junit.xml
                    '''
                }
            }
        }
        stage('Docker build') {
            steps { sh 'docker build -t "$IMAGE_NAME:$BUILD_NUMBER" .' }
        }
        stage('Docker smoke test') {
            steps {
                withCredentials([string(credentialsId: 'fastapi-ci-jwt-secret', variable: 'JWT_SECRET')]) {
                    sh '''
                        docker run -d --name "security-lab-$BUILD_NUMBER" -p 127.0.0.1:0:8000 -e JWT_SECRET "$IMAGE_NAME:$BUILD_NUMBER"
                        PORT=$(docker port "security-lab-$BUILD_NUMBER" 8000/tcp | awk -F: '{print $NF}')
                        for i in $(seq 1 30); do
                            if curl -fsS "http://127.0.0.1:$PORT/health"; then exit 0; fi
                            sleep 2
                        done
                        docker logs "security-lab-$BUILD_NUMBER"
                        exit 1
                    '''
                }
            }
        }
    }
    post {
        always {
            junit allowEmptyResults: true, testResults: 'junit.xml'
            archiveArtifacts allowEmptyArchive: true, artifacts: 'coverage.xml'
            sh 'docker rm -f "security-lab-$BUILD_NUMBER" >/dev/null 2>&1 || true'
        }
    }
}
