pipeline {
  agent any
  stages {
    stage('Checkout Scm') {
      steps {
        git(url: 'https://github.com/openportio/openport-go')
      }
    }
    stage('Run Tests') {
      steps {
        sh '''docker-compose up --build --abort-on-container-exit'''
      }
    }
  }
  post {
    always {
      sh '''docker-compose down'''
      sh '''docker system prune -f || true'''
      sh '''docker volume prune -f || true'''
      junit 'test-results/report.xml'
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
    timeout(time: 10, unit: 'MINUTES')
  }
  triggers {
    pollSCM('* * * * *')
  }
}