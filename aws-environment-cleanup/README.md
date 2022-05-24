### Overview

A script which cleans up AWS resources which could be leftover from day 2 tooling from a previous project I worked on. I developed this script entirely myself, I hope it shows my proficiency with Boto3.


### Resources Covered
1. NodeGroups. Delete via the EKS Console and it will go and remove all ASGs.
2. AWS EC2 Key Pair used for SSH onto worker Nodes.
3. Security Groups. Because Security Groups have interdependencies you need to clear all inbound rules in each group before being able to successfully remove.
4. Subnet tags for all subnets used for cluster nodes.
5. LoadBalancers.
6. EKS Managed Service.
7. Secrets Manager SSH Key Secrets. Via the console you can set a delete window of 7 days or you can force it immediately via the CLI.
8. CloudWatch Log Group.
9. DynamoDB items related to state locking.
10. S3 objects related to Terraform state for the cluster.
11. IAM Roles related to the cluster.
12. IAM OIDC Provider related to the cluster.
13. R53 records related to the cluster.
14. If using KMaaS for Secrets then delete the related K8s Auth Backend manually.
