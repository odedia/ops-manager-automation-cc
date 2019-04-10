
Configure your access to AWS:
```bash
aws configure
```

Provide your AWS Access Key and Secret. You can get them from the AWS console by clicking your username on the top right and selecting `My Security Credentials`. Make sure you choose the region you plan to deploy to (eu-west-2 shown below as an example):

```bash
AWS Access Key ID [****************AAAA]: 
AWS Secret Access Key [****************AAAA]: 
Default region name [eu-west-2]: 
Default output format [json]: 
```
Locate the AMI ID for Ubuntu 18.04 LTS for the region you plan to deploy to from [this list](https://cloud-images.ubuntu.com/locator/ec2/) and populate the AMI_ID variable:

`AMI_ID=ami-07dc734dc14746eab`

Create the jumpbox:

```bash
aws ec2 create-key-pair --key-name aws-pcf-jumpbox --query 'KeyMaterial' --output text > ~/.ssh/aws-pcf-jumpbox.pem
chmod 600 ~/.ssh/aws-pcf-jumpbox.pem
PCF_JUMPBOX_VPC_ID=`aws ec2 create-vpc --cidr-block 10.0.0.0/16 | jq -r .Vpc.VpcId`
PCF_JUMPBOX_SUBNET_ID=`aws ec2 create-subnet --vpc-id $PCF_JUMPBOX_VPC_ID --cidr-block 10.0.1.0/24 | jq -r .Subnet.SubnetId`
PCF_JUMPBOX_RESPONSE=`aws ec2 run-instances --image-id $AMI_ID --count 1 --instance-type m4.large --key-name aws-pcf-jumpbox --subnet-id $PCF_JUMPBOX_SUBNET_ID --associate-public-ip-address`
PCF_JUMPBOX_INSTANCE_ID=`echo $PCF_JUMPBOX_RESPONSE | jq -r .Instances[0].InstanceId`
echo "Sleeping for 3 minutes to make sure Jumpbox is up and has an external IP address..."
sleep 180s
JUMPBOX_IP_ADDRESS=`aws ec2 describe-instances --instance-ids $PCF_JUMPBOX_INSTANCE_ID | jq -r .Reservations[0].Instances[0].PublicIpAddress`
JUMPBOX_SG=`aws ec2 describe-instance-attribute --instance-id $PCF_JUMPBOX_INSTANCE_ID --attribute groupSet | jq -r .Groups[0].GroupId`


```

## Move to the jumpbox and log in to GCP

```bash
ssh ubuntu@$JUMPBOX_IP_ADDRESS -i ~/.ssh/aws-pcf-jumpbox.pem
```
  
