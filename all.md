## Sample Jenkinsfile
```
pipeline {
    agent any

    stages {
        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }
}
```


## Set a global agent
```
pipeline {
    agent {
                label ("Node2")
            }
    stages {
        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }
}
```

## Set multiple global agents

```
pipeline {
    agent {
                label ("Node1 || Node2 || Node3 || Node4")
            }
    stages {
        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }
}

```



# HOW TO SET NO AGENT 

```
pipeline {
    agent none

    stages {
        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }
}
```



## How set agent in stage

```
pipeline {
    agent any

    stages {

      stage('Hello') {
	agent { 
          label "node1"
           }
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }
}
```


## Define docker agent for a single stage

```
pipeline {
    agent any

    stages {

        stage('Hello') {
	 agent {
            docker {

              image 'maven:latest'
            }
           }
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }
}
```



## How to set global docker agent
```
pipeline {
    

agent {
    docker {
        image 'maven:3.8.1-adoptopenjdk-11'
        label 'my-defined-label'
        args  '-v /tmp:/tmp'
        args '-u root:root'
    }
}



    stages {
        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }
}
```



## How to set  TIMEOUT
```
pipeline {

    options {
      timeout(time: 1, unit: 'HOURS') 
  }  

agent any

    stages {
        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }
}
```


## How to set  environemnt in stage

```
pipeline {
    agent any
    stages {
        stage('Example') {
            environment { 
                AN_ACCESS_KEY = credentials('my-predefined-secret-text') 
            }
            steps {
                sh 'printenv'
            }
        }
    }
}
```


## How to add build trigger 
```
pipeline {
    agent any
    triggers {
        cron('H */4 * * 1-5')
    }
    stages {
        stage('Example') {
            steps {
                echo 'Hello World'
            }
        }
    }
}
```




## HOW TO SET buildDiscarder 

```
pipeline {
    agent any
options {
    buildDiscarder(logRotator(numToKeepStr: '20'))
    disableConcurrentBuilds()
    timeout (time: 60, unit: 'MINUTES')
    timestamps()
  }
    stages {
        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }
}
```


## HOW TO SET environment Variable

```
pipeline {
    agent any
  environment {
		DOCKERHUB_CREDENTIALS=credentials('dockerhub')
	}
    stages {
        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }
}
```

## HOW TO SET Parameters
```
pipeline {
    agent any

    stages {

        stage('Setup parameters') {
            steps {
                script {
                    properties([
                        parameters([
                        
                        choice(
                            choices: ['Dev', 'QA', 'Preprod', 'Prod'], 
                            name: 'Environment'
                                 
                                ),


                          string(
                            defaultValue: 'develop',
                            name: 'Area',
			    description: 'Enter the image Tag to deploy',
                            trim: true
                            ),
                        ])
                    ])
                }
            }
        }
 
        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }
}
```



## HOW TO SET SonarQube Block

```
pipeline {
    agent any

    stages {
         stage('SonarQube analysis') {
            agent {
                docker {
                  image 'sonarsource/sonar-scanner-cli:4.7.0'
                }
               }
               environment {
        CI = 'true'
        //  scannerHome = tool 'Sonar'
        scannerHome='/opt/sonar-scanner'
    }
            steps{
                withSonarQubeEnv('Sonar') {
                    sh "${scannerHome}/bin/sonar-scanner"
                }
            }
        }

        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }
}
```

## HOW TO waitForQualityGate Block

 stage("Quality Gate") {
            steps {
              timeout(time: 3, unit: 'MINUTES') {
                waitForQualityGate abortPipeline: true
              }
            }
          }


## HOW TO login in dockerhub

```
pipeline {
    agent any
  environment {
		DOCKERHUB_CREDENTIALS=credentials('dockerhub')
	}
    stages {

    stage('Login') {

			steps {
				sh 'echo $DOCKERHUB_CREDENTIALS_PSW | docker login -u $DOCKERHUB_CREDENTIALS_USR --password-stdin'
			}
		}

        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }
}
```



## Using Parameters in Jenkinsfile

```
pipeline {
    agent any
    stages {
        stage('Setup parameters') {
            steps {
                script { 
                    properties([
                        parameters([
                            choice(
                                choices: ['ONE', 'TWO'], 
                                name: 'PARAMETER_01'
                            ),
                            booleanParam(
                                defaultValue: true, 
                                description: '', 
                                name: 'BOOLEAN'
                            ),
                            text(
                                defaultValue: '''
                                this is a multi-line 
                                string parameter example
                                ''', 
                                 name: 'MULTI-LINE-STRING'
                            ),
                            string(
                                defaultValue: 'scriptcrunch', 
                                name: 'STRING-PARAMETER', 
                                trim: true
                            )
                        ])
                    ])
                }
            }
        }
    }   
}
```



## HOW TO SET condition

```
pipeline {
    agent any

    stages {

        stage('Setup parameters') {
            steps {
                script {
                    properties([
                        parameters([
                        
                        choice(
                            choices: ['Dev', 'QA', 'Preprod', 'Prod'], 
                            name: 'Environment'
                                 
                                ),


                          string(
                            defaultValue: 'develop',
                            name: 'Branch',
                            trim: true
                            ),
                        ])
                    ])
                }
            }
        }

        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }


    stage('build') {
      when{ 
          
          expression {
            env.Environment == 'Dev' }
          
            }
      
     steps {
         sh '''
       ls 
       pwd
                    '''
                }
            }

    stage('test') {
      when{ 
          
          expression {
            env.Environment == 'QA' }
          
            }
      
     steps {
         sh '''
       ls 
       pwd
                    '''
                }
            }

    stage('apply') {
      when{ 
          
          expression {
            env.Branch == 'Devops' }
          
            }
      
     steps {
         sh '''
       ls 
       pwd
                    '''
                }
            }


    stage('test') {
      when{ 
          
          expression {
            env.Branch == 'develop' }
          
            }
      
     steps {
         sh '''
       ls 
       pwd
                    '''
                }
            }


    }
}

```



## HOW TO SET  AND (&&) conditiion

```
pipeline {
    agent any

    stages {

        stage('Setup parameters') {
            steps {
                script {
                    properties([
                        parameters([
                        
                        choice(
                            choices: ['Dev', 'QA', 'Preprod', 'Prod'], 
                            name: 'Environment'
                                 
                                ),


                          string(
                            defaultValue: 'develop',
                            name: 'Branch',
                            trim: true
                            ),
                        ])
                    ])
                }
            }
        }
 
        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }


    stage('build') {
      when{ 
          
          expression {
            env.Environment == 'Dev' &&  env.Branch == 'develop'  }
          
            }
      
     steps {
         sh '''
       ls 
       pwd
        '''
                }
            }



    }
}
```



## HOW TO SET  OR (||) conditiion


```
pipeline {
    agent any

    stages {

        stage('Setup parameters') {
            steps {
                script {
                    properties([
                        parameters([
                        
                        choice(
                            choices: ['Dev', 'QA', 'Preprod', 'Prod'], 
                            name: 'Environment'
                                 
                                ),


                          string(
                            defaultValue: 'develop',
                            name: 'Branch',
                            trim: true
                            ),
                        ])
                    ])
                }
            }
        }
 
        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }


    stage('build') {
      when{ 
          
          expression {
            env.Environment == 'Dev' ||  env.Branch == 'develop'  }
          
            }
      
     steps {
         sh '''
       ls 
       pwd
        '''
                }
            }



    }
}
```

## Sample post condition slack
```
pipeline {
    agent any

    stages {
        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }

   post {
   
   success {
      slackSend (channel: '#development-alerts', color: 'good', message: "SUCCESSFUL: Application S4-EKTSS  Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
    }

 
    unstable {
      slackSend (channel: '#development-alerts', color: 'warning', message: "UNSTABLE: Application S4-EKTSS  Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
    }

    failure {
      slackSend (channel: '#development-alerts', color: '#FF0000', message: "FAILURE: Application S4-EKTSS Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
    }
   
    cleanup {
      deleteDir()
    }
}




}
```






## Sample post condition with Python interpreter
```
pipeline {
    agent any

    stages {
        stage('Setup parameters') {
            steps {
                script {
                    properties([
                        parameters([
                        
                        choice(
                                    choices: ['Yes', 'No'], 
                                    name: 'deployREDIS'
                           
                                ),

                             string(name: 'WARNTIME',
                             defaultValue: '2',
                            description: '''Warning time (in minutes) before starting upgrade'''),

                          string(
                                defaultValue: 'develop',
                                name: 'Please_leave_this_section_as_it_is',
                                trim: true
                            ),
                        ])
                    ])
                }
            }
        }
 
 
         //////////////////////////////////
       stage('warning') {
      steps {
        script {
            notifyUpgrade(currentBuild.currentResult, "WARNING")
            sleep(time:env.WARNTIME, unit:"MINUTES")
        }
      }
    }

        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }



post {
    always {
      script {
        notifyUpgrade(currentBuild.currentResult, "POST")
      }
    }
    
  }

}



def notifyUpgrade(String buildResult, String whereAt) {
  if (Please_leave_this_section_as_it_is == 'origin/develop') {
    channel = 'development-alerts'
  } else {
    channel = 'development-alerts'
  }
  if (buildResult == "SUCCESS") {
    switch(whereAt) {
      case 'WARNING':
        slackSend(channel: channel,
                color: "#439FE0",
                message: "Challenger: Upgrade starting in ${env.WARNTIME} minutes @ ${env.BUILD_URL}  Application CHALLENGER")
        break
    case 'STARTING':
      slackSend(channel: channel,
                color: "good",
                message: "Challenger: Starting upgrade @ ${env.BUILD_URL} Application CHALLENGER")
      break
    default:
        slackSend(channel: channel,
                color: "good",
                message: "Challenger: Upgrade completed successfully @ ${env.BUILD_URL}  Application CHALLENGER")
        break
    }
  } else {
    slackSend(channel: channel,
              color: "danger",
              message: "Challenger: Upgrade was not successful. Please investigate it immediately.  @ ${env.BUILD_URL}  Application CHALLENGER")
  }
}

```


## Sample post condition slack Multibranch pipeline

```
pipeline {
    agent any

    stages {
        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }
    }

   post {
   
   success {
      slackSend (channel: '#development-alerts', color: 'good', message: "SUCCESSFUL:  Branch name  <<${env.BRANCH_NAME}>>  Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
    }

 
    unstable {
      slackSend (channel: '#development-alerts', color: 'warning', message: "UNSTABLE:  Branch name  <<${env.BRANCH_NAME}>>  Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
    }

    failure {
      slackSend (channel: '#development-alerts', color: '#FF0000', message: "FAILURE:  Branch name  <<${env.BRANCH_NAME}>> Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' (${env.BUILD_URL})")
    }
   
    cleanup {
      deleteDir()
    }
}

}
```



## Query Jenkins Secret store

```
stage('backup') {

	      steps {
	        script {
	          withCredentials([
	            string(credentialsId: 'hostname', variable: 'HOSTNAME'),
	            string(credentialsId: 'username', variable: 'USERNAME'),
	            string(credentialsId: 'passwd', variable: 'PASSWORD')
	          ]) {

	            sh '''
                echo $HOSTNAME
                echo $USERNAME
                echo $PASSWORD
	            '''
	          }

	        }

	      }

	    }
```


## Query Jenkins Secret store

```
pipeline {
    agent any

    stages {
        stage('Hello') {
            steps {
                sh '''
                ls 
                pwd
                '''
            }
        }

    stage('backup') {

	      steps {
	        script {
	          withCredentials([
	            string(credentialsId: 'hostname', variable: 'HOSTNAME'),
	            string(credentialsId: 'username', variable: 'USERNAME'),
	            string(credentialsId: 'passwd', variable: 'PASSWORD')
	          ]) {

	            sh '''
                echo $HOSTNAME
                echo $USERNAME
                echo $PASSWORD
	            '''
	          }

	        }

	      }

	    }


    }
}
```

```
pipeline {
    agent any
    stages {
        stage('Example') {
            environment { 
                IMAGE = credentials('ubuntu') 
            }
            steps {
                sh '''
                docker run -i $IMAGE ls 
                '''
            }
        }
    }
}
```

## Raise Pull Request using Jenkins

```
stage('Raise PR') {
    agent {
        docker { image 'trussworks/gh-cli:dependabot-docker-cimg-python-3.10.6' }
    }
    steps {
        withVault(configuration: [disableChildPoliciesOverride: false, timeout: 60, vaultCredentialId: 'vaultCred', vaultUrl: 'http://vault.beitcloud.com:8200'], vaultSecrets: [[path: 'mycreds/github-creds', secretValues: [[envVar: 'GITHUB_TOKEN', vaultKey: 'github-token']]]]) {
            sh '''
            pwd
            ls -la $PWD
            chown jenkins:jenkins pr.sh || true
            chmod +x pr.sh || true
            tr -d "\\r" <pr.sh >a.tmp
            mv a.tmp pr.sh
            bash pr.sh
            '''
        }  
    }
}

stage('Remove Docker Image') {
    environment {
        IMAGE_NAME_TO_REMOVE = "trussworks/gh-cli:dependabot-docker-cimg-python-3.10.6"
    }
    steps {
        script {
            try {
                sh "docker rmi -f ${IMAGE_NAME_TO_REMOVE}"
            } catch (Exception e) {
                echo "Failed to remove Docker image: ${e}"
            }
        }
    }
}
```

## Dynamically fetch Dockerhub Credentials from Vault and update in "pass" for Jenkins use
```
stage('Fetch Docker Credentials from Vault and Update pass store') {
    steps {
        script {
            withVault(
                configuration: [
                    disableChildPoliciesOverride: false,
                    timeout: 60,
                    vaultCredentialId: 'vaultCred',
                    vaultUrl: "${env.VAULT_URL}"
                ],
                vaultSecrets: [
                    [
                        path: 'mycreds/dockerhub-creds/vidaldocker',
                        secretValues: [
                            [envVar: 'DOCKERHUB_USERNAME', vaultKey: 'username'],
                            [envVar: 'DOCKERHUB_PASSWORD', vaultKey: 'password']
                        ]
                    ]
                ]
            ) {
                // Fetch Docker credentials from Vault
                def dockerUsername = sh(script: "echo ${DOCKERHUB_USERNAME}", returnStdout: true).trim()
                def dockerPassword = sh(script: "echo ${DOCKERHUB_PASSWORD}", returnStdout: true).trim()

                // Update pass store with new credentials
                sh """
                    cd /var/lib/jenkins
                    echo ${dockerPassword} | docker login -u ${dockerUsername} --password-stdin
                    cd -
                """
            }
        }
    }
}
```

## Jenkins Warning Solution: Your password will be stored unencrypted in /var/lib/jenkins/.docker/config.json
```


The warning you are seeing indicates that the Docker client is storing your Docker credentials unencrypted on the filesystem. This can be a security risk, especially if the machine is shared or if it is not properly secured.
To avoid this, you can configure Docker to use a credential helper. Credential helpers store Docker credentials securely, often in a system-specific manner, such as using the operating system's secure credential storage mechanisms.
The purpose of using a GPG key for the password store in the context of Docker credentials is to securely encrypt and manage your sensitive data. 
Here’s how it works and how it relates to Jenkins credentials:

Purpose of GPG Key for the Password Store
GPG (GNU Privacy Guard) is a tool for secure communication and data storage. It is commonly used to encrypt data and create digital signatures. When you use GPG for a password store, it encrypts your passwords and other sensitive information, ensuring that only authorized users (those with the corresponding private key) can decrypt and access the data.

Using GPG with Docker Credentials
When you log in to Docker and store your credentials using docker login, the credentials are typically stored in plain text in a configuration file (~/.docker/config.json). This can be a security risk if someone gains access to this file.
By using GPG with a password store like pass, you can encrypt these credentials. Here’s a simplified flow:
Encrypt Credentials: The pass utility uses GPG to encrypt your Docker credentials and other secrets.
Secure Storage: Encrypted credentials are stored in the password store.
Decryption on Demand: When you need to use the credentials, pass decrypts them using your GPG key.

Here are the steps to configure a Docker credential helper:
Step 1: Install a Credential Helper AND GENERATE gpg key if you do not have any
Step 2: Initialize the Password Store (Linux Only)
Step 3: Configure Docker to Use the Credential Helper
Step 4: Log in to Docker
Step 5: Verify
You can verify that the credentials are stored using the configured credential helper by checking the contents of ~/.docker/config.json and ensuring that the credentials are not stored there directly.

Step 1: Install a Credential Helper: Install pass and docker-credential-pass:
# NOTE: Work as user jenkins
    sudo -u jenkins -i # switch to user jenkins and open a new shell
    sudo apt-get update
    sudo apt-get install pass -y # install pass
    wget https://github.com/docker/docker-credential-helpers/releases/download/v0.6.3/docker-credential-pass-v0.6.3-amd64.tar.gz
    tar -xvf docker-credential-pass-v0.6.3-amd64.tar.gz
    sudo mv docker-credential-pass /usr/local/bin/   # install docker-credential-pass
# Verify that /usr/local/bin/docker-credential-pass is executable OR chmod +x /usr/local/bin/docker-credential-pass && echo $PATH
    ls -l /usr/local/bin/docker-credential-pass
Output:    -rwxr-xr-x 1 root root 1234567 Jul 20 12:34 /usr/local/bin/docker-credential-pass

Step 1-1: GENERATE gpg key
    gpg --list-keys # to verify if you have a gpg key
    gpg --gen-key

Step 2: Initialize the Password Store (Linux Only)
    pass init "Your GPG Key ID"

Step 3: Configure Docker to Use the Credential Helper
    sudo -u jenkins -i
    mkdir -p ~/.docker
    vim  ~/.docker/config.json
    # Add the following content to configure Docker to use pass:
    {
        "credsStore": "pass"
    }
    cat ~/.docker/config.json

Step 4: Log in to Docker
    docker login -u your-docker-username
    OR
    echo "<DOCKER_PASSWORD>" | docker login -u "<DOCKER_USERNAME>" --password-stdin
    pass ls

Step 5: Verify
    You can verify that the credentials are stored using the configured credential helper by checking the contents of ~/.docker/config.json and ensuring that the credentials are not stored there directly.
    sudo -u jenkins -i
    cat ~/.docker/config.json

Step 6: Verify if pass is initialized 
    pass show docker-credential-helpers/docker-pass-initialized
          IF NOT INITIALIZED, DO
	echo "initialized" | pass insert -f docker-credential-helpers/docker-pass-initialized
	pass show docker-credential-helpers/docker-pass-initialized


RE-RUN YOUR JENKINS JOB AND ENSURE THERE ARE NO MORE PLAINTEXT PASSWORD STORED IN /var/lib/jenkins/.docker/config.json



