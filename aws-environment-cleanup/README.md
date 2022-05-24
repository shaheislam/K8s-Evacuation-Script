### Overview
A script which cleans up AWS resources which could be leftover from day 2 tooling from a previous project I worked on. I developed this script entirely myself, I hope it shows my proficiency with Boto3.


### Resources Covered
NodeGroups. Delete via the EKS Console and it will go and remove all ASGs.
AWS EC2 Key Pair used for SSH onto worker Nodes.
Security Groups. Because Security Groups have interdependencies you need to clear all inbound rules in each group before being able to successfully remove.
Subnet tags for all subnets used for cluster nodes.
LoadBalancers.
EKS Managed Service.
Secrets Manager SSH Key Secrets. Via the console you can set a delete window of 7 days or you can force it immediately via the CLI.
CloudWatch Log Group.
DynamoDB items related to state locking.
S3 objects related to Terraform state for the cluster.
IAM Roles related to the cluster.
IAM OIDC Provider related to the cluster.
R53 records related to the cluster.
If using KMaaS for Secrets then delete the related K8s Auth Backend manually.
