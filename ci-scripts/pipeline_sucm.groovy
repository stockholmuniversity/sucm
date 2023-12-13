#!/usr/bin/env groovy

def projectName = env.JOB_NAME
def revision
def tag


suSetProperties(["github": "true"])

node("agent") {
    stage("Cleanup workspace")
    {
        cleanWs()
    }

    stage("Prepare docker environment")
    {
        suDockerBuildAndPull(projectName)
    }

    docker.image(projectName).inside('-v /var/run/docker.sock:/var/run/docker.sock -v /local/jenkins/conf:/local/jenkins/conf -v /local/jenkins/libexec:/local/jenkins/libexec -v /etc/pip.conf:/etc/pip.conf') {
        suGitHubBuildStatus {

            stage("Get information")
            {
                revision = env.rev ?: sh(script: "git log -n 1  --pretty=format:'%H'", returnStdout: true).trim()
                tag = sh(script: "git tag --contains ${revision} | tail -1", returnStdout: true).trim()
            }

            suWithPoetryCredentials(tag: tag) {
                sh(script: "python3 -m poetry run python3 -m pylint *.py")
                sh(script: "python3 -m poetry run python3 -m isort --check --diff .")
            }
        }
    }
}
