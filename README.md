# ops-manager-automation-cc

## What is this?
This is a fork of https://github.com/amcginlay/ops-manager-automation-cc to target AWS deployments.

The following steps use [Control Tower](https://github.com/EngineerBetter/control-tower) to build a [Concourse](https://concourse-ci.org/) instance on [AWS](https://console.aws.amazon.com/), then uses a combination of [S3](https://console.aws.amazon.com/s3/home/) buckets, [Credhub](https://docs.cloudfoundry.org/credhub/), a suite of [Platform Automation](http://docs.pivotal.io/platform-automation) tools and a single Concourse pipeline to deploy (and upgrade) the entire OpsMan and PCF product stack directly from the [Pivotal Network](https://network.pivotal.io).

The pipelines currently support [Pivotal Container Service](https://pivotal.io/platform/pivotal-container-service) and [Pivotal Application Service](https://pivotal.io/platform/pivotal-application-service) with related products.

## Fork this repository

I recommend forking this repository so you can:

* Make modifications to suit your own requirements
* Protect your active pipelines from config changes made here

## Increase your Elastic IPs limit on AWS
I have reached the 5 EIP limit while trying to setup both PKS and Concourse. You should fill out a request form to increase this limit to 10. The form is available [Here](https://console.aws.amazon.com/support/cases#/create?issueType=service-limit-increase&limitType=service-code-elastic-ips).

## Create a jumpbox from your local machine 
Please use the EC2 Dashboard to create an Ubuntu 18.04 LTS EC2 instance with an m4.large instance type. Once done, ssh into the machine.

All following commands should be executed from the jumpbox unless otherwsie instructed.

## Prepare your environment file

```bash
> ~/.env                                                                     # (re)create empty file
echo "# *** your environment-specific variables will go here ***" >> ~/.env

echo "PIVNET_UAA_REFRESH_TOKEN=CHANGE_ME_PIVNET_UAA_REFRESH_TOKEN" >> ~/.env # e.g. xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-r
echo "PCF_DOMAIN_NAME=CHANGE_ME_DOMAIN_NAME" >> ~/.env                       # e.g. "mydomain.com", "pal.pivotal.io", "pivotaledu.io", etc.
echo "PCF_SUBDOMAIN_NAME=CHANGE_ME_SUBDOMAIN_NAME" >> ~/.env                 # e.g. "mypks", "mypas", "cls66env99", "maroon", etc.
echo "GITHUB_PUBLIC_REPO=CHANGE_ME_GITHUB_PUBLIC_REPO" >> ~/.env             # e.g. https://github.com/odedia/ops-manager-automation-cc.git

echo "export OM_TARGET=https://pcf.\${PCF_SUBDOMAIN_NAME}.\${PCF_DOMAIN_NAME}" >> ~/.env
echo "export OM_USERNAME=admin" >> ~/.env
echo "export OM_PASSWORD=$(uuidgen)" >> ~/.env
echo "export OM_DECRYPTION_PASSPHRASE=\${OM_PASSWORD}" >> ~/.env
echo "export OM_SKIP_SSL_VALIDATION=true" >> ~/.env
```

__Before__ continuing, open the `.env` file and update the `CHANGE_ME` values accordingly.

Ensure these variables get set into the shell every time the ubuntu user connects to the jumpbox:

```bash
echo "source ~/.env" >> ~/.bashrc
```

Load the variables into your shell with the source command so we can use them immediately:

```bash
source ~/.env
```

## Prepare jumpbox and generate service account

```bash

sudo apt update --yes && \
sudo apt install --yes jq && \
sudo apt install --yes build-essential && \
sudo apt install --yes ruby-dev && \
sudo apt install --yes python3-pip && \
sudo apt install --yes awscli


curl -sL https://deb.nodesource.com/setup_8.x | sudo -E bash -
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list

sudo apt-get update
sudo apt-get install git-core curl zlib1g-dev build-essential libssl-dev libreadline-dev libyaml-dev libsqlite3-dev sqlite3 libxml2-dev libxslt1-dev libcurl4-openssl-dev software-properties-common libffi-dev nodejs yarn

```

Configure your access to AWS:
```bash
aws configure
```

Provide your AWS Access Key and Secret. You can get them from the AWS console by clicking your username on the top right and selecting `My Security Credentials`:

```bash
AWS Access Key ID [****************AAAA]: 
AWS Secret Access Key [****************AAAA]: 
Default region name [eu-west-2]: 
Default output format [json]: 
```

```bash
cd ~

FLY_VERSION=5.0.1
wget -O fly.tgz https://github.com/concourse/concourse/releases/download/v${FLY_VERSION}/fly-${FLY_VERSION}-linux-amd64.tgz && \
  tar -xvf fly.tgz && \
  sudo mv fly /usr/local/bin && \
  rm fly.tgz
  
CT_VERSION=0.3.1
wget -O control-tower https://github.com/EngineerBetter/control-tower/releases/download/${CT_VERSION}/control-tower-linux-amd64 && \
  chmod +x control-tower && \
  sudo mv control-tower /usr/local/bin/

OM_VERSION=0.51.0
wget -O om https://github.com/pivotal-cf/om/releases/download/${OM_VERSION}/om-linux && \
  chmod +x om && \
  sudo mv om /usr/local/bin/

PN_VERSION=0.0.55
wget -O pivnet https://github.com/pivotal-cf/pivnet-cli/releases/download/v${PN_VERSION}/pivnet-linux-amd64-${PN_VERSION} && \
  chmod +x pivnet && \
  sudo mv pivnet /usr/local/bin/

BOSH_VERSION=5.4.0
wget -O bosh https://s3.amazonaws.com/bosh-cli-artifacts/bosh-cli-${BOSH_VERSION}-linux-amd64 && \
  chmod +x bosh && \
  sudo mv bosh /usr/local/bin/
  
CHUB_VERSION=2.2.1
wget -O credhub.tgz https://github.com/cloudfoundry-incubator/credhub-cli/releases/download/${CHUB_VERSION}/credhub-linux-${CHUB_VERSION}.tgz && \
  tar -xvf credhub.tgz && \
  sudo mv credhub /usr/local/bin && \
  rm credhub.tgz

TF_VERSION=0.11.13
wget -O terraform.zip https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_amd64.zip && \
  unzip terraform.zip && \
  sudo mv terraform /usr/local/bin && \
  rm terraform.zip
  
TAWS_VERSION=0.37.0
wget -O terraforming-aws.tar.gz https://github.com/pivotal-cf/terraforming-aws/releases/download/v${TAWS_VERSION}/terraforming-aws-v${TAWS_VERSION}.tar.gz && \
  tar -zxvf terraforming-aws.tar.gz && \
  rm terraforming-aws.tar.gz
```

```bash
cd ~

aws iam create-user --user-name pcf-installer
PCF_INSTALLER_RESPONSE_JSON=`aws iam create-access-key --user-name pcf-installer`
PCF_INSTALLER_ACCESS_KEY=`echo $PCF_INSTALLER_RESPONSE_JSON | jq -r .AccessKey.AccessKeyId`
PCF_INSTALLER_ACCESS_SECRET=`echo $PCF_INSTALLER_RESPONSE_JSON | jq -r .AccessKey.SecretAccessKey`
echo "PCF_INSTALLER_ACCESS_KEY=${PCF_INSTALLER_ACCESS_KEY}" >> ~/.env
echo "PCF_INSTALLER_ACCESS_SECRET=${PCF_INSTALLER_ACCESS_SECRET}" >> ~/.env
source ~/.env

aws iam create-group --group-name pcf-installer-group
aws iam attach-group-policy --group-name pcf-installer-group --policy-arn arn:aws:iam::aws:policy/AmazonEC2FullAccess
aws iam attach-group-policy --group-name pcf-installer-group --policy-arn arn:aws:iam::aws:policy/AmazonRDSFullAccess
aws iam attach-group-policy --group-name pcf-installer-group --policy-arn arn:aws:iam::aws:policy/AmazonRoute53FullAccess
aws iam attach-group-policy --group-name pcf-installer-group --policy-arn arn:aws:iam::aws:policy/AmazonS3FullAccess
aws iam attach-group-policy --group-name pcf-installer-group --policy-arn arn:aws:iam::aws:policy/AmazonVPCFullAccess
aws iam attach-group-policy --group-name pcf-installer-group --policy-arn arn:aws:iam::aws:policy/IAMFullAccess
aws iam attach-group-policy --group-name pcf-installer-group --policy-arn arn:aws:iam::aws:policy/AWSKeyManagementServicePowerUser
```

Create a custom policy as follows:

```bash
cat > ~/custom_pcf_policy.json <<-EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "KMSKeyDeletionAndUpdate",
            "Effect": "Allow",
            "Action": [
                "kms:UpdateKeyDescription",
                "kms:ScheduleKeyDeletion"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": "eu-west-2"
                }
            }
        }
    ]
}
EOF
```

__OR__ if you want to limit the deployment to a single region only, use the following:

```
cat > ~/custom_pcf_policy.json <<-EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "KMSKeyDeletionAndUpdate",
            "Effect": "Allow",
            "Action": [
                "kms:UpdateKeyDescription",
                "kms:ScheduleKeyDeletion"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "aws:RequestedRegion": "eu-west-2"
                }
            }
        }
    ]
}
EOF
```
Continue creating permissions and service accounts:

```bash
PCF_INSTALLER_POLICY_ARN=`aws iam create-policy --policy-name custom_pcf_policy --policy-document file:///home/ubuntu/custom_pcf_policy.json | jq -r .Policy.Arn`
aws iam attach-group-policy --group-name pcf-installer-group --policy-arn $PCF_INSTALLER_POLICY_ARN
aws iam add-user-to-group --user-name pcf-installer --group-name pcf-installer-group

```
## Clone this repo

The scripts, pipelines and config you need to complete the following steps are inside this repo, so clone it to your jumpbox:

```bash
git clone ${GITHUB_PUBLIC_REPO} ~/ops-manager-automation-cc
```

## Create a self-signed certificate

Run the following script to create a certificate and key for the installation:

```bash
DOMAIN=${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME} ~/ops-manager-automation-cc/bin/mk-ssl-cert-key.sh
```

## Configure Terraform

```bash
cat > ~/terraform.tfvars <<-EOF
env_name               = "${PCF_SUBDOMAIN_NAME}"
access_key         = "${PCF_INSTALLER_ACCESS_KEY}"
secret_key         = "${PCF_INSTALLER_ACCESS_SECRET}"
region             = "eu-west-2"
availability_zones = ["eu-west-2a", "eu-west-2b", "eu-west-2c"]
ops_manager_ami    = ""
rds_instance_count = 0
dns_suffix         = "${PCF_DOMAIN_NAME}"
vpc_cidr           = "10.0.0.0/16"
use_route53        = true
use_tcp_routes     = true
ssl_cert           = <<SSL_CERT
$(cat ~/certs/${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}.crt)
SSL_CERT
ssl_private_key     = <<SSL_KEY
$(cat ~/certs/${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}.key)
SSL_KEY
EOF
```

Note the `opsman_image_url == ""` setting which prohibits Terraform from downloading and deploying the Ops Manager VM.
The Concourse pipelines will take responsibility for this.

## Terraform the infrastructure

The PKS and PAS platforms have different baseline infrastructure requirements which are configured from separate dedicated directories.
Terraform is directory-sensitive and needs local access to your customized `terraform.tfvars` files so symlink it in from the home directory.

### If you're targetting PAS ...

```bash
echo "PRODUCT_SLUG=cf" >> ~/.env
cd ~/terraforming/terraforming-pas
ln -s ~/terraform.tfvars .
```

### ... or, if you're targetting PKS

```bash
echo "PRODUCT_SLUG=pivotal-container-service" >> ~/.env
cd ~/terraforming/terraforming-pks
ln -s ~/terraform.tfvars .
```

### Launch Terraform

Confirm you're in the correct directory for your chosen platform and `terraform.tfvars` is present, then execute the following:

```bash
terraform init
terraform apply --auto-approve
```

This will take about 2 mins to complete.

## Install Concourse

We use Control Tower to install Concourse, as follows:

```bash
AWS_ACCESS_KEY_ID=$PCF_INSTALLER_ACCESS_KEY \
AWS_SECRET_ACCESS_KEY=$PCF_INSTALLER_ACCESS_SECRET \
control-tower deploy \
    --region eu-west-2 \
    --iaas aws \
    --workers 3 \
    ${PCF_SUBDOMAIN_NAME}
```

This will take about 20 mins to complete.

## Persist a few credentials

```bash
INFO=$(AWS_ACCESS_KEY_ID=$PCF_INSTALLER_ACCESS_KEY AWS_SECRET_ACCESS_KEY=$PCF_INSTALLER_ACCESS_SECRET \
  control-tower info \
    --region eu-west-2 \
    --iaas aws \
    --json \
    ${PCF_SUBDOMAIN_NAME}
)

echo "CC_ADMIN_PASSWD=$(echo ${INFO} | jq --raw-output .config.concourse_password)" >> ~/.env
echo "CREDHUB_CA_CERT='$(echo ${INFO} | jq --raw-output .config.credhub_ca_cert)'" >> ~/.env
echo "CREDHUB_CLIENT=credhub_admin" >> ~/.env
echo "CREDHUB_SECRET=$(echo ${INFO} | jq --raw-output .config.credhub_admin_client_secret)" >> ~/.env
echo "CREDHUB_SERVER=$(echo ${INFO} | jq --raw-output .config.credhub_url)" >> ~/.env
echo 'eval "$(AWS_ACCESS_KEY_ID=$PCF_INSTALLER_ACCESS_KEY AWS_SECRET_ACCESS_KEY=$PCF_INSTALLER_ACCESS_SECRET \
  control-tower info \
    --region eu-west-2 \
    --iaas aws \
    --env ${PCF_SUBDOMAIN_NAME})"' >> ~/.env

source ~/.env
```

## Verify BOSH and Credhub connectivity

```bash
bosh env
credhub --version
```

## Check Concourse targets and check the pre-configured pipeline:

```bash
fly targets
fly -t control-tower-${PCF_SUBDOMAIN_NAME} pipelines
```

Navigate to the `url` shown for `fly targets`.

Use `admin` user and the value of `CC_ADMIN_PASSWD` to login and see the pre-configured pipeline.

__Note__ `control-tower` will log you in but valid access tokens will expire every 24 hours. The command to log back in is:

```bash
fly -t control-tower-${PCF_SUBDOMAIN_NAME} login --insecure --username admin --password ${CC_ADMIN_PASSWD}
```

## Set up dedicated GCS bucket for downloads

-----------

```bash
aws s3api create-bucket --bucket ${PCF_SUBDOMAIN_NAME}-concourse-resources --region eu-west-2 --create-bucket-configuration LocationConstraint=eu-west-2
aws s3api put-bucket-versioning --bucket ${PCF_SUBDOMAIN_NAME}-concourse-resources --versioning-configuration Status=Enabled
```

## Add a dummy state file

The `state.yml` file is produced by the `create-vm` platform automation task and serves as a flag to indicate that an Ops Manager exists.
We currently store the `state.yml` file in S3.
The `install-opsman` job also consumes this file so it can short-circuit the `create-vm` task if an Ops Manager does exist.
This is a mandatory input and does not exist by default so we create a dummy `state.yml` file to kick off proceedings.
Storing the `state.yml` file in git may work around this edge case but, arguably, GCS/S3 is a more appropriate home.

```bash
echo "---" > ~/state.yml

aws s3api put-object --bucket ${PCF_SUBDOMAIN_NAME}-concourse-resources --key state.yml --body state.yml
```

If you manage your domain name outside of AWS's route53, you need to set the NS records accordingly to what is shows in the route53 hosted zone.

List the hosted zones using this command:

`aws route53 list-hosted-zones`

Find the hosted zone for the current deployment. Get the details about this hosted zone:

`aws route53 get-hosted-zone --id <hoste-zone-id from previous command>`

Copy the values from the `name servers`, for example:

```
    "DelegationSet": {
        "NameServers": [
            "ns-1806.awsdns-33.co.uk",
            "ns-1248.awsdns-28.org",
            "ns-670.awsdns-19.net",
            "ns-441.awsdns-55.com"
        ]
    }
```

Set these records in your external domain registrar (such as Google Domains) as NS records.

Wait until the update is propagated but getting a response to this command:

`dig +short pcf.${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}`


Make sure you are in the right directory.
### If you're targetting PAS ...

```bash
cd ~/terraforming/terraforming-pas
echo "PCF_INSTALLATION_KIND=pas" >> ~/.env
echo "PCF_REGION=`terraform output region`" >> ~/.env
source ~/.env
```

### ... or, if you're targetting PKS


## Store secrets in Credhub

```bash
cd ~/terraforming/terraforming-pks
echo "PCF_INSTALLATION_KIND=pks" >> ~/.env
echo "PCF_REGION=`terraform output region`" >> ~/.env
source ~/.env

```

```bash
credhub set -n pivnet-api-token -t value -v "${PIVNET_UAA_REFRESH_TOKEN}"
credhub set -n domain-name -t value -v "${PCF_DOMAIN_NAME}"
credhub set -n subdomain-name -t value -v "${PCF_SUBDOMAIN_NAME}"
credhub set -n opsman-public-ip -t value -v "$(dig +short pcf.${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME})"
credhub set -n om-target -t value -v "${OM_TARGET}"
credhub set -n om-skip-ssl-validation -t value -v "${OM_SKIP_SSL_VALIDATION}"
credhub set -n om-username -t value -v "${OM_USERNAME}"
credhub set -n om-password -t value -v "${OM_PASSWORD}"
credhub set -n om-decryption-passphrase -t value -v "${OM_DECRYPTION_PASSPHRASE}"
credhub set -n domain-crt-ca -t value -v "$(cat ~/certs/${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}.ca.crt)"
credhub set -n domain-crt -t value -v "$(cat ~/certs/${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}.crt)"
credhub set -n domain-key -t value -v "$(cat ~/certs/${PCF_SUBDOMAIN_NAME}.${PCF_DOMAIN_NAME}.key)"
credhub set -n vms_security_group_id -t value -v "$(terraform output vms_security_group_id)"
credhub set -n ops_manager_ssh_public_key_name -t value -v "$(terraform output ops_manager_ssh_public_key_name)"
credhub set -n infrastructure_subnet_ids_1 -t value -v "$(terraform output infrastructure_subnet_ids | sed -n 1p | sed s'/.$//')"
credhub set -n infrastructure_subnet_ids_2 -t value -v "$(terraform output infrastructure_subnet_ids | sed -n 2p | sed s'/.$//')"
credhub set -n infrastructure_subnet_ids_3 -t value -v "$(terraform output infrastructure_subnet_ids | sed -n 3p)"
credhub set -n pcf_subnet_ids_1 -t value -v "$(terraform output ${PCF_INSTALLATION_KIND}_subnet_ids | sed -n 1p | sed s'/.$//')"
credhub set -n pcf_subnet_ids_2 -t value -v "$(terraform output ${PCF_INSTALLATION_KIND}_subnet_ids | sed -n 2p | sed s'/.$//')"
credhub set -n pcf_subnet_ids_3 -t value -v "$(terraform output ${PCF_INSTALLATION_KIND}_subnet_ids | sed -n 3p)"
credhub set -n services_subnet_ids_1 -t value -v "$(terraform output services_subnet_ids | sed -n 1p | sed s'/.$//')"
credhub set -n services_subnet_ids_2 -t value -v "$(terraform output services_subnet_ids | sed -n 2p | sed s'/.$//')"
credhub set -n services_subnet_ids_3 -t value -v "$(terraform output services_subnet_ids | sed -n 3p)"
credhub set -n pcf_installation_kind -t value -v "${PCF_INSTALLATION_KIND}"

credhub set -n region -t value -v "$(terraform output region)"
credhub set -n az1 -t value -v "$(terraform output infrastructure_subnet_availability_zones | sed -n 1p | sed s'/.$//')"
credhub set -n az2 -t value -v "$(terraform output infrastructure_subnet_availability_zones | sed -n 2p | sed s'/.$//')"
credhub set -n az3 -t value -v "$(terraform output infrastructure_subnet_availability_zones | sed -n 3p)"

credhub set -n pks_master_iam_instance_profile_name -t value -v "$(terraform output pks_master_iam_instance_profile_name)"
credhub set -n pks_worker_iam_instance_profile_name -t value -v "$(terraform output pks_worker_iam_instance_profile_name)"

credhub set -n aws-access-key-id -t value -v "${PCF_INSTALLER_ACCESS_KEY}"
credhub set -n aws-secret-access-key -t value -v "${PCF_INSTALLER_ACCESS_SECRET}"

credhub set -n vpc_subnet_id -t value -v "$(terraform output public_subnets | sed -n 1p | sed s'/.$//')"
credhub set -n ops_manager_iam_instance_profile_name -t value -v "$(terraform output ops_manager_iam_instance_profile_name)"
credhub set -n ops_manager_ssh_public_key_name -t value -v "$(terraform output ops_manager_ssh_public_key_name)"
credhub set -n vms_security_group_id -t value -v "$(terraform output vms_security_group_id)"
credhub set -n ssh_private_key -t value -v "$(terraform output ops_manager_ssh_private_key)"

```
Take a moment to review these settings with `credhub get -n <NAME>`.

## Build the pipeline

Create a `private.yml` to contain the secrets required by `pipeline.yml`:

```bash
cat > ~/private.yml << EOF
---
product-slug: ${PRODUCT_SLUG}
config-uri: ${GITHUB_PUBLIC_REPO}
s3-bucket: ${PCF_SUBDOMAIN_NAME}-concourse-resources
aws-access-key-id: ${PCF_INSTALLER_ACCESS_KEY}
aws-secret-access-key: ${PCF_INSTALLER_ACCESS_SECRET}
region: ${PCF_REGION}
pivnet-token: ${PIVNET_UAA_REFRESH_TOKEN}
credhub-ca-cert: |
$(echo $CREDHUB_CA_CERT | sed 's/- /-\n/g; s/ -/\n-/g' | sed '/CERTIFICATE/! s/ /\n/g' | sed 's/^/  /')
credhub-client: ${CREDHUB_CLIENT}
credhub-secret: ${CREDHUB_SECRET}
credhub-server: ${CREDHUB_SERVER}
EOF
```

Set and unpause the pipeline:

```bash
fly -t control-tower-${PCF_SUBDOMAIN_NAME} set-pipeline -p ${PRODUCT_SLUG} -n \
  -c ~/ops-manager-automation-cc/ci/${PRODUCT_SLUG}/pipeline.yml \
  -l ~/private.yml

fly -t control-tower-${PCF_SUBDOMAIN_NAME} unpause-pipeline -p ${PRODUCT_SLUG}
```

This should begin to execute in ~60 seconds.

Be aware that you may be required to manually accept the PivNet EULAs before a product can be downloaded
so watch for pipeline failures which contain the necessary URLs to follow.

You may also observe that on the first run, the `export-installation` job will fail because the Ops Manager
is missing.
Run this job manually once the `install-opsman` job has run successfully.

## Teardown

The following steps will help you when you're ready to dispose of everything.

Use the `om` tool to delete the installation (be careful, you will __not__ be asked to confirm this operation):

```bash
om delete-installation
```

Delete the Ops Manager VM:

```bash
gcloud compute instances delete "ops-manager-vm" --zone "us-central1-a" --quiet
```

Unwind the remaining PCF infrastructure:

```bash
cd ~/terraforming/terraforming-pks
terraform destroy --auto-approve
```

Unintstall Concourse with `control-tower`:

```bash
GOOGLE_APPLICATION_CREDENTIALS=~/gcp_credentials.json \
  control-tower destroy \
    --region us-central1 \
    --iaas gcp \
    ${PCF_SUBDOMAIN_NAME}
```
