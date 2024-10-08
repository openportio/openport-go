pipeline {
  agent any
  stages {
    stage('Run Tests') {
      steps {
        bitbucketStatusNotify(buildState: 'INPROGRESS')
        sh './jenkins.sh || true'
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
    unsuccessful {
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
        bitbucketStatusNotify(buildState: 'FAILED')
    }
    success {
        bitbucketStatusNotify(buildState: 'SUCCESSFUL')
    }
  }
  options {
    timeout(time: 60, unit: 'MINUTES')
  }
  triggers {
    pollSCM('* * * * *')
  }
}