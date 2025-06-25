#!/usr/bin/env groovy

node {
    common = load '/opt/jenkins/terraform/common.groovy'
}

def INFRAENV = "${JOB_NAME}".split('-')[1].split('/')[0].toLowerCase()
def PUBLIC_REGISTRY = 'harbor.riaint.ee/proxy-hub.docker.com'
def HARBOR_REGISTRY = 'harbor.riaint.ee'

pipeline {
    agent any
    parameters {
        gitParameter(name: 'Branch',
                branchFilter: 'origin/(.*)',
                type: 'PT_BRANCH',
                defaultValue: 'develop',
                selectedValue: 'DEFAULT',
                sortMode: 'ASCENDING',
                listSize: '12',
                description: 'Git branch to create the docker image from')
        booleanParam(name: 'BuildAndPush', defaultValue: true, description: 'Build and push docker image')
        booleanParam(name: 'TriggerDeploy', defaultValue: true, description: 'Trigger deployment to nodes')
        booleanParam(name: 'runSonar', defaultValue: true, description: 'Run SonarQube scanner')
        booleanParam(name: 'runOwaspCheck', defaultValue: true, description: 'Run OWASP check')
        

    }

    environment {
        BRANCH_NAME = "${params.Branch}"
        GIT_BRANCH_NAME = "${BRANCH_NAME.split("/")[-1]}"
        PROJECT_NAME = 'rig'
        IMAGE_NAME = readMavenPom().getArtifactId()
        RELEASE_VERSION = readMavenPom().getVersion()

        // calculate package version
        MAIN_VERSION = "${RELEASE_VERSION}-${BUILD_NUMBER}"
        RC_VERSION = "${RELEASE_VERSION}-${GIT_COMMIT[0..7]}-rc.${BUILD_NUMBER}"
        DEV_VERSION = "${RELEASE_VERSION}-${GIT_COMMIT[0..7]}-dev.${BUILD_NUMBER}"

        PACKAGE_VERSION = "${BRANCH_NAME == 'main' ? env.MAIN_VERSION : BRANCH_NAME == 'develop' ? env.RC_VERSION : env.DEV_VERSION}"

        DOCKER_IMAGE = "${PROJECT_NAME}/${IMAGE_NAME}:${PACKAGE_VERSION}"
        TAG_NAME = "v${PACKAGE_VERSION}"
    }
    options {
        ansiColor('xterm')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        disableConcurrentBuilds()
        timestamps()
    }
    stages {
        stage('Print input parameters') {
            steps {
                echo "GIT_BRANCH: ${GIT_BRANCH}"
                echo "GIT_BRANCH_NAME: ${GIT_BRANCH_NAME}"
                echo "Branch: ${params.Branch}"
                
                echo "BuildAndPush: ${params.BuildAndPush}"
                echo "TriggerDeploy: ${params.TriggerDeploy}"

                script {
                    // add always correct displayName
                    currentBuild.displayName = "${PACKAGE_VERSION}"
                }
            }
        }
        stage('Build and test application') {
            when {
                expression { params.BuildAndPush }
            }
            steps {
                sh "echo 'app.name=${PROJECT_NAME}-${IMAGE_NAME}' > ./src/main/resources/heartbeat.properties"
                sh "echo 'app.version=${PACKAGE_VERSION}' >> ./src/main/resources/heartbeat.properties"
                sh "echo 'app.packaging.time=${currentBuild.startTimeInMillis}' >> ./src/main/resources/heartbeat.properties"

                sh('docker run --rm' +
                        ' --volume "$HOME/.m2:/var/maven/.m2"' +
                        ' --volume "/var/run/docker.sock:/var/run/docker.sock"' +
                        ' --volume "$PWD:$PWD"' +
                        ' --workdir $PWD' +
                        ' -e TESTCONTAINERS_CHECKS_DISABLE=true' +
                        ' -e TESTCONTAINERS_HUB_IMAGE_NAME_PREFIX=harbor.riaint.ee/proxy-hub.docker.com/' +
                        ' harbor.riaint.ee/proxy-hub.docker.com/library/maven:3.8.5-openjdk-17' +
                        ' mvn --batch-mode --settings settings.xml --update-snapshots -Duser.home=/var/maven' +
                        ' clean -U package')
            }
        }
        stage('Build and push docker image to Harbor') {
            when {
                expression { params.BuildAndPush }
            }
            steps {
                script {
                    def appImage = docker.build("${DOCKER_IMAGE}", ['.'].join(' '))
                    docker.withRegistry("https://${HARBOR_REGISTRY}", 'harbot-rig') {
                        appImage.push()
                        appImage.push("develop")   // devel docker image version for all docker images

                        if (BRANCH_NAME == 'develop') {
                            PACKAGE_VERSION_PARTS = PACKAGE_VERSION.split("-").first().split("\\.")

                            DOCKER_MAJOR_TAG = PACKAGE_VERSION_PARTS[0]
                            DOCKER_MINOR_TAG = DOCKER_MAJOR_TAG + "." + PACKAGE_VERSION_PARTS[1]
                            DOCKER_PATCH_TAG = DOCKER_MINOR_TAG + "." + PACKAGE_VERSION_PARTS[2]

                            appImage.push(DOCKER_MAJOR_TAG)
                            appImage.push(DOCKER_MINOR_TAG)
                            appImage.push(DOCKER_PATCH_TAG)
                        }
                    }
                  
                    currentBuild.description = "Built Docker image: <strong>${DOCKER_IMAGE}</strong><br/>Git tag: <strong>${TAG_NAME}</strong>"
                }
            }
        }
        stage('Tag commit') {
            when {
                expression { params.BuildAndPush }
            }
            environment {
                BITBUCKET_SSH = credentials('bitbucket-ssh')
            }
            steps {
                sh "git tag ${TAG_NAME}"
                sh "git push origin ${TAG_NAME}"
            }
        }
        stage('Trigger deploy') {
            when {
                expression { params.BuildAndPush && params.TriggerDeploy }
            }
            steps {
                build wait: false, job: 'rig-update-version', parameters: [
                        string(name: 'role', value: 'timur'),
                        string(name: 'role_version', value: "${TAG_NAME}"),
                        string(name: 'docker_images', value: "${DOCKER_IMAGE}")
                ]
            }
        }
        stage("OWASP Dependency-Check") {
            when {
                expression { params.runOwaspCheck }
            }
            steps {
                // remove reports folder
                sh "rm -r $HOME/ria_sr_cache/dependency-check-report | true"

                // Separate dependency check cache by OWASP dependency check major version
                sh('mkdir --parents "$HOME/ria_sr_cache/owasp-dependency-check/data/10"')
                sh('mkdir --parents "$HOME/ria_sr_cache/dependency-check-report"')

                sh('docker run --rm ' +
                    '--volume ./:/project ' +
                    '--volume $HOME/ria_sr_cache/owasp-dependency-check/data/10:/usr/share/dependency-check/data ' +
                    '--volume $HOME/ria_sr_cache/dependency-check-report:/project/dependency-check-report ' +
                    '--user $(id -u):$(id -g) ' +
                    'harbor.riaint.ee/proxy-hub.docker.com/owasp/dependency-check:10.0.3 ' +
                    '--format XML ' +
                    '--format HTML ' +
                    '--hostedSuppressionsUrl https://nexus.riaint.ee/repository/raw-public/jeremylong/DependencyCheck/raw/main/core/src/main/resources/dependencycheck-base-suppression.xml ' +
                    // '--suppression /project/suppressions.xml ' +
                    // '--nvdValidForHours 23 ' +
                    '--scan /project/. ' +
                    // Golang analyzers are experimental
                    '--enableExperimental ' +
                    '--log /project/dependency-check-report/dependency-check.log ' +
                    '--out /project/dependency-check-report')

                sh('mv ${HOME}/ria_sr_cache/dependency-check-report/ ./ | true')

                dependencyCheckPublisher pattern: '**/dependency-check-report.xml'
                sh "rm -r ./dependency-check-report | true"

            }
        }

        stage("SonarQube analysis") {
            when {
                expression { params.runSonar }
            }
            steps {
                script {
                    CURRENT_DIR = pwd()

                    sh "mkdir -p ${CURRENT_DIR}/build"

                    withCredentials([string(credentialsId: 'RiaSonarQube', variable: 'SONAR_TOKEN')]) {
                        sh('docker run --rm' +
                                ' --volume "/var/run/docker.sock:/var/run/docker.sock"' +
                                ' --volume "$PWD:$PWD"' +
                                ' --workdir $PWD' +
                                " ${PUBLIC_REGISTRY}/maven:3.8.5-openjdk-17 " +
                                ' mvn sonar:sonar ' +
                                ' -Dsonar.projectKey=rig-ee.eesti.timur ' +
                                ' -Dsonar.projectName=rig-ee.eesti.timur ' +
                                " -Dsonar.projectVersion=${PACKAGE_VERSION} " +
                                ' -Dsonar.host.url=https://sonarqube.riaint.ee ' +
                                ' -Dsonar.tests=src/test/ ' +
                                ' -Dsonar.java.codeCoveragePlugin=jacoco ' +
                                ' -Dsonar.junit.reportPaths=build/test-results/test ' +
                                ' -Dsonar.sourceEncoding=UTF-8 ' +
                                ' -Dsonar.analysisCache.enabled=false ' +
                                ' -Dsonar.exclusions=ansible/**,gradle/**,img/**,**/*.yml ' +
                                ' -Dsonar.issue.ignore.multicriteria=S3437,S4502,S4684,UndocumentedApi,BoldAndItalicTagsCheck ' +
                                ' -Dsonar.issue.ignore.multicriteria.S3437.resourceKey=src/main/java/**/* ' +
                                ' -Dsonar.issue.ignore.multicriteria.S3437.ruleKey=squid:S3437 ' +
                                ' -Dsonar.issue.ignore.multicriteria.UndocumentedApi.resourceKey=src/main/java/**/* ' +
                                ' -Dsonar.issue.ignore.multicriteria.UndocumentedApi.ruleKey=squid:UndocumentedApi ' +
                                ' -Dsonar.issue.ignore.multicriteria.S4502.resourceKey=src/main/java/**/* ' +
                                ' -Dsonar.issue.ignore.multicriteria.S4502.ruleKey=java:S4502 ' +
                                ' -Dsonar.issue.ignore.multicriteria.S4684.resourceKey=src/main/java/**/* ' +
                                ' -Dsonar.issue.ignore.multicriteria.S4684.ruleKey=java:S4684 ' +
                                ' -Dsonar.issue.ignore.multicriteria.BoldAndItalicTagsCheck.resourceKey=src/main/webapp/app/**/*.* ' +
                                ' -Dsonar.issue.ignore.multicriteria.BoldAndItalicTagsCheck.ruleKey=Web:BoldAndItalicTagsCheck ' +
                                " -Dsonar.login=${SONAR_TOKEN} ")
                    }

                    sh "sudo rm -rf ${CURRENT_DIR}/build  | true"
                }
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        failure {
            mail to: "rig-tehniline@ria.ee", 
                subject: "RIG CI ERROR: ${env.JOB_NAME}", 
                body: """<b>${env.JOB_NAME} build failed!</b><br>
                Project: ${env.JOB_NAME} <br>
                Build parameters: <br>
                - Branch: ${params.Branch}<br>
                - Build and Push: ${params.BuildAndPush}<br>
                - Trigger deploy: ${params.TriggerDeploy}<br>
                - Run Sonarqube: ${params.runSonar}<br>
                - Run OWASP Check: ${params.runOwaspCheck}<br><br>
                Build Number: ${env.BUILD_NUMBER} <br> 
                URL of build: ${env.BUILD_URL}""", 
                charset: 'UTF-8', 
                mimeType: 'text/html';
        }
    }
}
