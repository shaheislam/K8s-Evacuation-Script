'''
# Destroy
Destroy EKS-related Resources.

# What
Running `destroy.py` after a Terraform Destroy of 'infra' should ensure that the entire footprint of an EKS Cluster is removed.

# Why
* We found the Terraform Destroy for 'apps' - the k8s-related module of modules - to be unreliable.
* We need to Destroy things that were created in Terraform with local provisioners and so are not tracked in state.
* Some insurance for if any problems occur in the Terraform Destroy step.
* First function checks if cluster itself has been deleted, if not then script exits to preserve terraform state and rerun Destroy.
'''

#!/usr/bin/env python3
import pprint
import sys

import boto3
import botocore
import os
import hvac

import time

ACCOUNT_NAME = sys.argv[1]
REGION = sys.argv[2]
CLUSTER_NAME = sys.argv[3]
FLAG = sys.argv[4]  # This flag decides if the infra part to be destroyed or not.
# Give "1" if you want to destroy cluster before deleting other resources or "0" to delete stale resources only when cluster is already destroyed.


def check_eks_cluster(cluster_name,aws_region):
    print('Checking if EKS Cluster has been deleted.')
    try:
        eks_client = boto3.client("eks",aws_region)
        list_of_clusters = eks_client.list_clusters()['clusters']
        if cluster_name in list_of_clusters:
            if(FLAG=="1"):
                print("Checking if nodes associated with this cluster exists")
                if(check_eks_cluster_nodes(cluster_name,aws_region) is True):
                    print("destroying the cluster now")
                    destroy_cluster(cluster_name,aws_region)
                else:
                    if(delete_node_group(cluster_name,aws_region)):
                        print("destroying the cluster now")
                        destroy_cluster(cluster_name,aws_region)
                    else:
                        print("Can't proceed to delete cluster when node group associated still exists")
                        sys.exit(1)
            else:
                print("cluster "+cluster_name+" still exists , So exiting from the script without destroying stale resources")
                sys.exit(1)
        else:
            print("cluster "+cluster_name+" does not exist in given aws region, Can proceed to delete stale resources")
    except Exception as e:
        print(str(e))
        sys.exit(1)


def check_eks_cluster_nodes(cluster_name,aws_region):
    try:
        node_filter = [{
            "Name": "tag:kubernetes.io/cluster/" + cluster_name,
            "Values": ["owned"]
        }]
        ec2_client = boto3.client('ec2',aws_region)
        eks_nodes = ec2_client.describe_instances(Filters=node_filter)
        reservations = eks_nodes["Reservations"]
        if reservations == []:
            return True
        else:
            nodes_not_in_terminated_status=0
            for r in reservations:
                instances = r['Instances']
                for i in instances:
                    if i['State']['Name'] != "terminated":
                        nodes_not_in_terminated_status+=1
            if (nodes_not_in_terminated_status==0):
                return True
            else:
                return False
    except Exception as e:
        print(str(e))
        pass

def delete_node_group(cluster_name,aws_region):

    try:
        t_end = time.time() + 1800
        client = boto3.client('eks',aws_region)
        response = client.delete_nodegroup(
        clusterName=cluster_name,
        nodegroupName=f"{cluster_name}-workers"
        )
        flag = False
        print("Node group getting destroyed !! Might take few minutes for completion!.")
        while time.time() < t_end :
            nodegroups_list = client.list_nodegroups(clusterName=cluster_name)
            if (check_eks_cluster_nodes(cluster_name,aws_region) is True and len(nodegroups_list['nodegroups'])==0):
                flag = True
                break
        return flag

    except Exception as e:
        print(str(e))
        pass


def destroy_cluster(cluster_name,aws_region):

    client = boto3.client("eks",aws_region)
    try:
        t_end = time.time() + 360
        response = client.delete_cluster(
        name = cluster_name
        )
        print("Cluster getting destroyed !! , Might take few minutes for completion!")
        while time.time() < t_end :
            list_of_clusters = client.list_clusters()['clusters']
            if cluster_name not in list_of_clusters:
                return True

    except Exception as e:
        print("The exception is this: " + str(e))
        pass


def s3_tfstate_object(account_name, region, cluster_name):
    print('Delete State Objects.')
    try:
        bucket_name = f"{account_name}-{region}-terraform-remote-state-app-creator"
        object_key = f"epaas-eks/{cluster_name}/"
        s3_resource = boto3.resource('s3')
        bucket = s3_resource.Bucket(bucket_name)
        bucket.objects.filter(Prefix=object_key).delete()
        print("Deleted: " + object_key)
    except Exception as e:
        print(str(e))
        pass


def dynamodb_tfstate_item(account_name, region, cluster_name):
    print('Deleting DynamoDB State Item')
    try:
        client = boto3.client('dynamodb')
        stages = ['infra', 'apps', 'postbuild']
        for stage in stages:
            item = account_name + '-' + region + '-terraform-remote-state-app-creator/epaas-eks/' + cluster_name + '/' + stage + '/terraform.tfstate-md5'
            resp = client.list_tables()
            for tables in resp['TableNames']:
                if "app-creator" in tables:
                    table = tables
                    client.delete_item(
                        TableName=table,
                        Key={
                            "LockID":
                                {"S": item
                                    }
                        },
                    )
                    print("Deletion of '" + item + "' complete.")
    except Exception as e:
        print("The exception is this: " + str(e))
        pass


def load_balancers(cluster_name,aws_region):
    print('Deleting Cluster Load Balancers')
    try:
       cluster_tags=[f"kubernetes.io/cluster/{cluster_name}","elbv2.k8s.aws/cluster"]
       client = boto3.client('elbv2',aws_region)
       for cluster_tag in cluster_tags:
            resp = client.describe_load_balancers()
            for lb in resp["LoadBalancers"]:
                arn=lb["LoadBalancerArn"]
                name=lb["LoadBalancerName"]
                tags=client.describe_tags(ResourceArns=[
                    arn
                ],)
                for tag in tags["TagDescriptions"][0]['Tags']:
                    if tag['Key'] == cluster_tag:
                            client.delete_load_balancer(
                            LoadBalancerArn=arn)
                            print("Deletion of '" + name + "' load balancer complete.")
    except botocore.exceptions.ClientError as e:
       if e.response['Error']['Code'] == 'LoadBalancerNotFoundException':
           pprint.pprint("The ELB was not found.")
    except Exception as e:
        print("The exception is this: " + str(e))



def subnet_tags(cluster_name,aws_region):
    print('Deleting Cluster Subnet Tags')
    try:
        cluster_tag=f"kubernetes.io/cluster/{cluster_name}"
        client = boto3.client('ec2',aws_region)

        resp = client.describe_subnets()
        for subnet in resp['Subnets']:
            SubnetId = subnet['SubnetId']
            for tag in subnet['Tags']:
                if tag['Key'] == cluster_tag:
                    client.delete_tags(
                        Resources=[SubnetId
                    ],
                            Tags=[
                            {
                                'Key': tag['Key'],
                                'Value': tag['Value'],
                            },
                        ],
                    )
                    print("Deletion of '" + tag['Key'] + "' tag complete.")
    except Exception as e:
        print("The exception is this: " + str(e))


def node_ssh_secrets(cluster_name,aws_region):
    print('Deleting Cluster SSH Key Secrets')
    try:
        client = boto3.client('secretsmanager',aws_region)
        paginator = client.get_paginator('list_secrets')
        secrets_list_iterator = paginator.paginate()
        nodes_ssh_key = f"{cluster_name}-managed-nodes-ssh-key"
        for secretsList in secrets_list_iterator:
            for secret in secretsList['SecretList']:
                if nodes_ssh_key in secret["Name"]:
                    client.delete_secret(
                        SecretId=secret["Name"],
                        ForceDeleteWithoutRecovery=True)
                    print("Deletion of '" + secret["Name"] + "' complete.")
    except Exception as e:
        print("The exception is this: " + str(e))


def security_groups(cluster_name,aws_region):
    # This variabe will need to be changed if Terraform EFS SG setting changes
    retry_count=0
    client = boto3.client('ec2',aws_region)
    print("Deleting security groups if exists")
    groups = [f"{cluster_name}-worker-sg" , f"{cluster_name}-cluster-sg"]
    while(retry_count<2):
        retry_count+=1 #Running the loop for 2 times as the worker SG is not getting deleted in first try.
        for group_name in groups:
            print(group_name)
            response = client.describe_security_groups(
                Filters=[
                    {"Name": "group-name", "Values": [group_name]}
                ]
            )
            if response['SecurityGroups'] == []:
                print("Security group '" + group_name + "' does not exist, skipping...")
            else:
                for sg in response['SecurityGroups']:
                    # print(sg['IpPermissions'])
                    if sg['IpPermissions'] == []:
                        print("Ingress rules for security group '" + group_name + "' do not exist, skipping...")
                    else:
                        try:
                            client.revoke_security_group_ingress(GroupId=sg['GroupId'], IpPermissions = sg['IpPermissions'])
                        except ClientError as e:
                            print("The exception in revoking Ingress rules is this: " + str(e))
                    if sg['IpPermissionsEgress'] == []:
                        print("Egress rules for security group '" + group_name + "' do not exist, skipping...")
                    else:
                        try:
                            client.revoke_security_group_egress(GroupId=sg['GroupId'], IpPermissions = sg['IpPermissionsEgress'])
                        except ClientError as e:
                            print("The exception in revoking Egress rules is this: " + str(e))

                    group_id = response['SecurityGroups'][0]['GroupId']
                    try:
                        client.delete_security_group(
                            GroupId=group_id,
                        )
                        print("Deletion of SecurityGroup '" + group_name + "' complete.")
                    except Exception as e:
                        print("The exception in deleting SecurityGroup is this: " + str(e))


def cloud_watch_logs(cluster_name,aws_region):

    cloud_watch_group_name = f"/aws/eks/{cluster_name}/cluster"
    client = boto3.client('logs', region_name=aws_region)
    try:
        response = client.describe_log_groups()
        cloudwatch_log_groups_list=[]
        for log_group in response["logGroups"]:
            cloudwatch_log_groups_list.append(log_group['logGroupName'])
        if(cloud_watch_group_name in cloudwatch_log_groups_list):
            response = client.delete_log_group(
                logGroupName=cloud_watch_group_name
            )
            print("Log Group deleted successfully")
        else:
            print("The specified cloudwatch log group doesn't exist")
    except Exception as e:
        print("The given cloudwatch log group doesn't exist")
        pass


def delete_key_pairs(cluster_name,aws_region):

    key_name = f"epaas-eks-{cluster_name}-managed-nodes"
    ec2 = boto3.client('ec2',aws_region)
    keypairs = ec2.describe_key_pairs()
    all_keypairs=[]
    for keypair in keypairs["KeyPairs"]:
        all_keypairs.append(keypair["KeyName"])
    try:
        if key_name in all_keypairs:
            response = ec2.delete_key_pair(KeyName = key_name)
            print("key pair deleted successfully")
        else:
            print("The specified key pair does not exist")
    except Exception as e:
        print("The exception is this: " + str(e))


def delete_launch_template(cluster_name,aws_region):
    print('Deleting the Launch Template if exists')
    launch_template_names=[]
    ec2 = boto3.client('ec2',aws_region)
    response=ec2.describe_launch_templates()
    launch_templates= response["LaunchTemplates"]
    for launch_template in launch_templates:
        launch_template_names.append(launch_template['LaunchTemplateName'])
    for item in launch_template_names:
        if f"{cluster_name}-workers" in item:
            ec2.delete_launch_template(LaunchTemplateName=item)
            print("deleted launch template successfully")


def delete_vault_auth_backend(cluster_name,account_name):
    print('Deleting the Vault auth method if exists')
    if 'prod' in account_name.lower() and 'not-prod' not in account_name.lower() and 'non-prod' not in account_name.lower():
        vault_server = ""  # for prod accounts
    else:
        vault_server = ""  # for dev and test accounts
    vault_role = f"{account_name}-role-vault-aws-auth"
    aws_credentials = boto3.Session().get_credentials()
    vault_client = hvac.Client(url=vault_server, verify=False, namespace=f"aws/{account_name}")
    vault_client.auth.aws.iam_login(
        aws_credentials.access_key, aws_credentials.secret_key, aws_credentials.token, role=vault_role
    )
    backend_auth_path = f"kmaas-{cluster_name}-backend"
    try:
        vault_client.sys.disable_auth_method(path=backend_auth_path,)
        print(f"Deleted the Auth method: {backend_auth_path}")
    except Exception as e:
        print(f"The exception is this: {str(e)}")

def delete_iam_roles(cluster_name,account_name,aws_region):
    print('Deleting Roles if Exists')
    old_role_prefix=f"epaas-eks-{cluster_name}"
    new_role_prefix=f"{account_name}-epaas-{cluster_name}"
    role_suffix_list=['-aws-load-balancer-controller', '-aws-node', '-cluster-autoscaler', '-efs-csi', '-external-dns', '-jenkins', '-metricbeat']
    iam_client = boto3.client('iam',aws_region)
    response=iam_client.list_roles(MaxItems=1000)['Roles']
    iam_roles_list=[]
    for role in response:
        iam_rolename=role['RoleName']
        iam_roles_list.append(iam_rolename)
    for iam_role in iam_roles_list:
        if str(iam_role).startswith(old_role_prefix) or str(iam_role).startswith(new_role_prefix):
            for role_suffix in role_suffix_list:
                if f"{old_role_prefix}{role_suffix}"==iam_role or f"{new_role_prefix}{role_suffix}"==iam_role:
                    print(iam_role)
                    policy_arn_list = []
                    policy_names_list=[]
                    # To get the list of attached policies to a Role
                    try:
                        customer_managed_policy_paginator = iam_client.get_paginator('list_role_policies')
                        aws_managed_policy_paginator = iam_client.get_paginator('list_attached_role_policies')
                        for custom_response in customer_managed_policy_paginator.paginate(RoleName=iam_role,PaginationConfig={'MaxItems': 1000}):
                            account_id = boto3.client('sts').get_caller_identity().get('Account')
                            arn=f"arn:aws:iam::{account_id}:policy/"
                            for policy_name in custom_response.get('PolicyNames'):
                                policy=arn+policy_name
                                policy_arn_list.append(policy)
                                policy_names_list.append(policy_name)

                        for aws_response in aws_managed_policy_paginator.paginate(RoleName=iam_role,PaginationConfig={'MaxItems': 1000}):
                            for policy in aws_response.get('AttachedPolicies'):
                                policy_arn_list.append(policy['PolicyArn'])
                                policy_names_list.append(policy['PolicyName'])
                    except Exception as e:
                        print(f"The exception is this: {str(e)}")
                        pass

                    # To delete the attached custom policies to Role
                    for policy_name in policy_names_list:
                        try:
                            iam_client.delete_role_policy(RoleName = iam_role,PolicyName=policy_name)
                        except Exception as e:
                            pass

                    # To detach the attached aws managed policies to Role
                    for policy_arn in policy_arn_list:
                        try:
                            iam_client.detach_role_policy(RoleName=iam_role,PolicyArn=policy_arn)
                        except Exception as e:
                            pass

                    # To delete the Role
                    try:
                        iam_client.delete_role(RoleName = iam_role)
                        print(f"Deleted Iam Role :{iam_role}")
                    except Exception as e:
                        print(f"The exception is this: {str(e)}")
                        pass


def delete_secrets_manager(cluster_name,aws_region):
    secrets_client = boto3.client('secretsmanager',aws_region)
    secret_name=f"kmaas-{cluster_name}-epaas-eks"
    try:
        secrets_client.delete_secret(SecretId=secret_name, ForceDeleteWithoutRecovery=True)
    except Exception as e:
        print(f"The exception is this: {str(e)}")
        pass

def route53_externaldns_records_cleanup(cluster_name):

    records_to_delete = []
    r53 = boto3.client('route53')
    zones = r53.list_hosted_zones_by_name()

    if not zones or len(zones['HostedZones']) == 0:
        print("Could not find any DNS zone, Skipping...")
        return
    try:
        for zone in zones['HostedZones']:
            print("=======================")
            print("Scanning the zone for external dns records, "+zone['Name'])
            zone_id = zone['Id']
            records_to_delete = get_externaldns_route53_record(r53, zone_id, cluster_name)

            if len(records_to_delete) == 0:
                print("No external dns records found in Route53 Zone, Skipping...")
            else:
                print('Total externaldns records: ' + str(len(records_to_delete)))
                for record_delete in records_to_delete:
                    print("deleting: "+record_delete+" ...")
                    delete_externaldns_route53_record(r53, zone_id, record_delete)
    except Exception as e:
        print(f"The exception in route53 cleanup, please check: {str(e)}")
        pass


def get_externaldns_route53_record(r53, zone_id, cluster_name):

    dns_records = []
    external_dns_records = []
    dns_in_iteration = r53.list_resource_record_sets(HostedZoneId=zone_id)
    dns_records.extend(dns_in_iteration['ResourceRecordSets'])

    while 'NextRecordName' in dns_in_iteration.keys():
        next_record_name = dns_in_iteration['NextRecordName']
        dns_in_iteration = r53.list_resource_record_sets(HostedZoneId=zone_id, StartRecordName=next_record_name)
        dns_records.extend(dns_in_iteration['ResourceRecordSets'])

    for record in dns_records:
        if record['Type'] == 'TXT':
            if "heritage=external-dns,external-dns/owner="+cluster_name+",external-dns/resource" in record['ResourceRecords'][0]['Value']:
                for record_sub in dns_records:
                    if record_sub['Type'] in ['A', 'CNAME']:
                        if record_sub['Name'] in record['Name']:
                            external_dns_records.append(record['Name'])
                            external_dns_records.append(record_sub['Name'])

    return(external_dns_records)

def delete_externaldns_route53_record(r53, zone_id,record_name):
    del_record_response = r53.list_resource_record_sets(HostedZoneId=zone_id, StartRecordName=record_name, MaxItems='1')
    record_to_delete = del_record_response['ResourceRecordSets'][0]
    r53.change_resource_record_sets(
        HostedZoneId=zone_id,
        ChangeBatch={
            'Changes': [{
                'Action': 'DELETE',
                'ResourceRecordSet': record_to_delete
            }]
        }
    )
    print('deleted: ' + record_to_delete['Name'])

# Check if cluster and node group exist. If so , ask input from user if they need to proceed deleting them.
check_eks_cluster(CLUSTER_NAME,REGION)

# Resources have been deleted. Proceed.
s3_tfstate_object(ACCOUNT_NAME, REGION, CLUSTER_NAME)
dynamodb_tfstate_item(ACCOUNT_NAME, REGION, CLUSTER_NAME)
load_balancers(CLUSTER_NAME,REGION)
subnet_tags(CLUSTER_NAME,REGION)
node_ssh_secrets(CLUSTER_NAME,REGION)
security_groups(CLUSTER_NAME,REGION)
cloud_watch_logs(CLUSTER_NAME,REGION)
delete_key_pairs(CLUSTER_NAME,REGION)
delete_launch_template(CLUSTER_NAME,REGION)
delete_vault_auth_backend(CLUSTER_NAME,ACCOUNT_NAME)
delete_iam_roles(CLUSTER_NAME,ACCOUNT_NAME,REGION)
delete_secrets_manager(CLUSTER_NAME,REGION)
route53_externaldns_records_cleanup(CLUSTER_NAME)
