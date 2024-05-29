# Cloud Conformity Pipeline Scanner

<img src="images/Trend-Micro-Logo.png">

Pipeline scanner uses Vision One Cloud Posture's [Template Scanner](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-template-scanner_001) to secure your CloudFormation templates **before** they're deployed.

## Requirements

* Have an [Vision One](https://signin-xdr.visionone.trendmicro.com/) account.
* A cloud formation template to be scan.

## Usage

To use the script, specify the following required environment variables:
  * `v1_apikey` (Vision One API KEY)
  * `templatePath` (Path of the template to be scanned)
  * `templatesDirPath` (OPTIONAL. Location of the directory of templates to be scanned, (e.g., templates). This ignores the value of 'templatePath' if supplied.)
  * `maxExtreme | maxVeryHigh | maxHigh | maxMedium | maxLow` (Choose one or more of the options and set a number of how many violations are accepted)
  * `cc_output_result` (Either true or false, defaults to false. If set to true, it outputs the detected risks, instead of just the amount.)
  * `accountId` (OPTIONAL. Provides an account Id to be used by the scanner.)

 **PS.: ALWAYS use secrets to expose your credentials!**

## GitHub Actions Example

Add an Action in your `.github/workflow` yml file to scan your cloud formation template with Cloud One Conformity.

```yml
name: My CI/CD Pipeline

on: 
  push:
    branches: 
      - main
      
jobs:      
    CloudFormation-Scan:
       runs-on: ubuntu-latest
       steps:
          - name: Checkout
            uses: actions/checkout@v2
          - name: Cloud Posture Conformity Pipeline Scanner
            uses: igorschultz/cloud-posture-template-scanner-pipeline@version
            env:
              cc_apikey: ${{ secrets.apikey }}
              maxExtreme: 0
              maxVeryHigh: 1
              maxHigh: 3
              maxMedium: 5
              maxLow: 10
              templatePath: template/infrastructure.yaml
              templatesDirPath: templates # This is an example to scan all the templates inside the folder "templates"
              cc_output_results: true
```

## Docker Container Example

To be able to scan your template using a Docker comtainer, follow the example below:

https://hub.docker.com/r/raphabot/conformity-template-scanner-pipeline

```bash
docker run -v /home/ec2-user/dynamotest.template:/app/dynamotest.template -e cc_apikey=$MYAPIKEY -e maxExtreme=0 -e maxVeryHigh=0
-e maxHigh=0 -e maxMedium=0 -e maxLow=0 -e templatePath=infrastructure.yaml -cc_output_results=true felipecosta09/conformity-template-scanner-pipeline:latest
```

**PS.: To be able to scan a local template from a machine or inside a pipeline, the parameter "-v" is required in the docker run command, the example specifies a local file being copied to the container that will scan the Cloud Formation template ```/home/ec2-user/dynamotest.template:/app/dynamotest.template```, where:**

* **/home/ec2-user/dynamotest.template** - Represent the absolute path of the local Cloud Formation template file to be scanned;
* **/app/dynamotest.template** - The path where the file will be copied **(ONLY CHANGE THE FILE NAME OF THE TEMPLATE)**;

## Node CLI Example

To run the scanner in the Node CLI, just set the envinronment variables before execute the node script:

```bash
cc_apikey=$MYAPIKEY maxExtreme=0 maxVeryHigh=0 maxHigh=0 maxMedium=0 maxLow=0 templatePath=infrastructure.yaml cc_output_results=true node scan.js
```

## Contributing

If you encounter a bug, think of a useful feature, or find something confusing
in the docs, please
[create a new issue](https://github.com/igorschultz/cloud-posture-template-scanner-pipeline/issues/new)!

We :heart: pull requests. If you'd like to fix a bug, contribute to a feature or
just correct a typo, please feel free to do so.

## Support

Official support from Trend Micro is not available. Individual contributors may
be Trend Micro employees, but are not official support.
