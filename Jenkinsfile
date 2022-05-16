pipeline {
  agent any
  stages {
    stage('Checkout Scm') {
      steps {
        git(url: 'bitbucket.org:jan_de_bleser/openport-go-client.git', credentialsId: 'b92c4920-b14b-4568-9840-df41de323726')
      }
    }
    stage('Run Tests') {
      steps {
        sh '''cd openport-go-client && docker-compose up --build --abort-on-container-exit'''
      }
    }
  }
  post {
    always {
      sh '''cd openport-go-client && docker-compose down'''
      sh '''docker system prune -f || true'''
      sh '''docker volume prune -f || true'''
      junit 'openport-go-client/test-results/report.xml'
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