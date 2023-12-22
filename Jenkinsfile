pipeline {
  agent any
  stages {
    stage('Run Tests') {
      steps {
        sh '''rm -rf test-results/*'''
        sh '''docker compose up --build --abort-on-container-exit'''
        sh '''cd python_tests ; make test'''
      }
    }
  }
  post {
    always {
      sh '''docker-compose down'''
      sh '''docker system prune -f || true'''
      sh '''docker volume prune -f || true'''
      junit 'test-results/*.xml'
    }
    failure {
        mail(
            body: "<br>Project: ${env.JOB_NAME} <br>Build Number: ${env.BUILD_NUMBER} <br>build: ${env.BUILD_URL}",
            cc: '',
            charset: 'UTF-8',
            from: '',
            mimeType: 'text/html',
            replyTo: '',
            subject: "ERROR CI: ${env.JOB_NAME}",
            to: "jandebleser@gmail.com"
        )
    }
  }
  options {
    timeout(time: 60, unit: 'MINUTES')
  }
  triggers {
    pollSCM('* * * * *')
  }
}