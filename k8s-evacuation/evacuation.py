# -*- coding: utf-8 -*-
# pylint: disable=W1203,E1205,C0301


from ast import Pass, arg
import os
import argparse
import logging
import json
import colorlog
import boto3
import kubernetes
from kubernetes import config, client
from sys import platform


eksclient = boto3.client('eks')
asgclient = boto3.client('autoscaling')
ec2client = boto3.client('ec2')


""" Implements custom logger utilising colorlog """
logger = logging.getLogger('log')
if not logger.handlers:
    handler = colorlog.StreamHandler()
    handler.setFormatter(
        colorlog.ColoredFormatter(
            '%(log_color)s%(asctime)s %(levelname)s:\t%(name)s:%(message)s', datefmt='%m-%d %H:%M:%S'
        )
    )
    logger = colorlog.getLogger('log')
    logger.addHandler(handler)


def autoscaler_health_check():
    """ Checks the autoscaler is in a running state within the cluster """
    k8s_api = client.CoreV1Api()
    kube_system_pods = k8s_api.list_namespaced_pod(namespace='kube-system').items
    for pod in kube_system_pods:
        if 'cluster-autoscaler' in pod.metadata.name and pod.status.phase.lower() == "running":
            logger.debug(f"Listing unhealthy autoscaler pods with their IPs: \nThis pod {pod.metadata.name} is unhealthy with a status of {pod.status.phase} in namespace {pod.metadata.namespace}. \nFull details: {pod.metadata.name}, {pod.metadata.namespace}, {pod.status.pod_ip}, {pod.status.phase}")


def autoscaler_logs(cluster):
    """ If debug is enabled, outputs autoscaler logs to stdout """
    try:
        k8s_api = client.CoreV1Api()
        kube_system_pods = k8s_api.list_namespaced_pod(namespace='kube-system').items
        for pod in kube_system_pods:
            if 'cluster-autoscaler' in pod.metadata.name :
                logs = k8s_api.read_namespaced_pod_log(name=pod.metadata.name, namespace='kube-system')
                with open('logs.txt', 'w', encoding="utf-8") as log_file:
                    log_file.write(logs)
                with open('logs.txt', "r", encoding="utf-8") as read_handler:
                    logger.debug(read_handler.read(-50))
                os.remove('logs.txt')
    except Exception as error:
        if '401' in str(error):
            logging.error(f"401 Unauthorized error for cluster '{cluster}'")
        else:
            logging.error(f"The exception is this: {str(error)}")


def cluster_retrieval():
    """ Retrieves all EKS clusters from account """
    cluster_dict = eksclient.list_clusters()
    cluster_list = cluster_dict['clusters']
    return cluster_list


def current_capacity():
    """ If debug enabled prints current capacity of nodes """
    k8s_api = client.CoreV1Api()
    nodes = k8s_api.list_node().items
    for node in nodes:
        api_response = k8s_api.read_node_status(node.metadata.name)
        logger.debug("Node IP: " + str(node.metadata.name) + "\nNode capacity: " + str(api_response.status.capacity) + "\nAllocatable Capacity: " + str(api_response.status.allocatable))


def cordon_node(availability_zone):
    """ Cordons nodes within specified AZ to prevent them from being scheduled on """
    nodes = nodes_in_affected_availability_zone(availability_zone)
    k8s_api = client.CoreV1Api()
    body = {
        "spec": {
            "unschedulable": True
        }
    }
    for node in nodes:
        response = k8s_api.patch_node(node, body)
        logger.debug(response)


def drain_affected_node(availability_zone):
    """ Drains pods from affected nodes within specified AZ """
    k8s_api = client.CoreV1Api()
    nodes = nodes_in_affected_availability_zone(availability_zone)
    namespaces = k8s_api.list_namespace().items
    for namespace in namespaces:
        pods = k8s_api.list_namespaced_pod(namespace.metadata.name).items
        for pod in pods:
            metadata_node_ip = pod.spec.node_name
            if metadata_node_ip in nodes:
                logger.debug(pod.metadata.name)
                eviction_body = client.V1Eviction(metadata=client.V1ObjectMeta(name=pod.metadata.name, namespace=pod.metadata.namespace, deletion_grace_period_seconds=30))
                logger.debug(eviction_body)
                eviction_deletion = client.V1DeleteOptions()
                try:                    
                    eviction_response = k8s_api.create_namespaced_pod_eviction(pod.metadata.name, pod.metadata.namespace, eviction_body)
                    logger.debug(eviction_response)
                except Exception as error:
                    logger.error(f"Failed to evict pod {pod.metadata.name}: {error.body}: {eviction_deletion}")


def evacuation_process(cluster, process, availability_zone=None):
    """ Runs evacuation process on a specific cluster or all clusters depending on argument passed at CLI """
    kubeconfig_context(cluster)
    load_kube_config()
    try:
        if process == 'capacity':
            current_capacity()
        elif process == 'evacuate':
            nodegroups = eksclient.list_nodegroups(clusterName=cluster)
            if len(nodegroups['nodegroups']) > 0:
                autoscaler_health_check()
                autoscaler_logs(cluster)
                update_asg(cluster, availability_zone, process, account=None)
                cordon_node(availability_zone)
                drain_affected_node(availability_zone)
    except Exception as error:
        if '401' in str(error):
            logger.error(f"401 Unauthorized error for cluster '{cluster}'")
        else:
            logger.error(f"The exception is this: {str(error)}")


def get_all_subnetids(account):
    subnet_ids=[]
    subnets = ec2client.describe_subnets()
    for subnet in subnets['Subnets'] :
        for tag in subnet['Tags']:
            if tag['Key'] == 'Name':
                if (f"{account}-vpc-private" in str(tag['Value'])):
                    subnet_ids.append(subnet['SubnetId'])
    logger.debug(subnet_ids)
    return subnet_ids


def get_subnets(cluster, availability_zone):
    """ Retrieves subnets for affected AZ """
    subnet_list=[]
    asgs = asgclient.describe_auto_scaling_groups()['AutoScalingGroups']
    for asg in asgs:
        asg_id = asg['Tags'][0]['ResourceId']
        if f"eks-{cluster}-workers" in asg_id:
            asg_dict = asgclient.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_id])
            logger.debug(asg_dict)
            subnets = asg_dict['AutoScalingGroups'][0]['VPCZoneIdentifier'].split(',')
            for subnet in subnets:
                response = ec2client.describe_subnets(SubnetIds=[subnet])
                subnet = response['Subnets'][0]['SubnetId']
                availability_zone_response = response['Subnets'][0]['AvailabilityZone']
                if availability_zone_response != availability_zone:
                    subnet_list.append(subnet)
            logger.debug(f"The list of subnets is {subnet_list} along with the autoscaling group '{asg_id}'")
            return subnet_list, asg_id


def restoration_process(cluster, account, process, availability_zone=None):
    """ Runs restoration process on a specific cluster or all clusters depending on argument passed at CLI """
    try:
        update_asg(cluster, availability_zone, process, account)
    except Exception as error:
        logger.error(f"The exception is this: {str(error)}")


def kubeconfig_context(cluster):
    """ Kubeconfig set context to specified cluster defined at CLI """
    os.system(f"aws eks update-kubeconfig --name {cluster}")


def load_kube_config():
    """ Load kube config to interact with Kubernetes Python client """
    if platform == "linux" or platform == "linux2":
        config.load_kube_config(config_file="/opt/app/config") # from BuildKite
    else:
        config.load_kube_config(config_file="~/.kube/config")   # from Local
    return client


def nodes_in_affected_availability_zone(availability_zone):
    """ Capture list of nodes in affected AZ """
    k8s_api = client.CoreV1Api()
    response = k8s_api.list_node()
    node_details = {}
    affected_nodes = []
    for node_metadata in response.items:
        for key,value in node_metadata.metadata.labels.items():
            if key == "failure-domain.beta.kubernetes.io/zone" and value == availability_zone:
                affected_nodes.append(node_metadata.metadata.name)
                node_details[value]=node_metadata.metadata.name
    logger.debug(affected_nodes)
    return affected_nodes


def update_asg(cluster, availability_zone, process, account):
    """ Update ASG to remove subnet within affected AZ """
    if(process == 'evacuate'):
        subnet_list = get_subnets(cluster,availability_zone)[0]
    elif(process == 'restore'):
        subnet_list = get_all_subnetids(account)
    subnet_string  = ','.join(subnet_list)
    asg_name = get_subnets(cluster, availability_zone)[1]
    asgclient.update_auto_scaling_group(AutoScalingGroupName=asg_name,VPCZoneIdentifier=subnet_string)
    response = asgclient.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
    vpc_zone = response['AutoScalingGroups'][0]['VPCZoneIdentifier']
    availability_zones = ", ".join(response['AutoScalingGroups'][0]['AvailabilityZones'])
    logger.debug("Updated ASG Details: \nVPCZone Identifier: " + vpc_zone + "\nAvailabilityZones: " + availability_zones)

def terminate_node(nodeId):
    """Terminate ec2 node"""
    ec2_resource = boto3.resource('ec2')
    instance = ec2_resource.Instance(nodeId)
    try:
        logger.info(f'Terminating EKS node: {nodeId}!!!')
        instance.terminate()
        logger.info(f'Waiting for EKS node: {nodeId} to terminate!!!')
        instance.wait_until_terminated()
        logger.info(f'EKS node {nodeId} has been terminated!!!')
    except Exception as error:
        if '401' in str(error):
            logger.error(f"401 Unauthorized error for node '{nodeId}'")
        else:
            logger.error(f"The exception is this: {str(error)}")

def nodeId_of_schedulingDisabledNode_from_availability_zone(availability_zone):
    """ Capture list of nodes which has status schedulingDisabled in specific AZ """
    k8s_api = client.CoreV1Api()
    response = k8s_api.list_node()

    schedulingDisabled_nodeID = []
    for node_metadata in response.items:
        for key,value in node_metadata.metadata.labels.items():
            if key == "failure-domain.beta.kubernetes.io/zone" and value == availability_zone:
                if node_metadata.spec.taints:
                    for taint in node_metadata.spec.taints:
                        if taint.key == "node.kubernetes.io/unschedulable" and taint.effect == "NoSchedule":
                            for key, value in node_metadata.metadata.annotations.items():
                                if key == "csi.volume.kubernetes.io/nodeid":
                                    convertedDict = json.loads(value)
                                    node_id = convertedDict["efs.csi.aws.com"]
                                    schedulingDisabled_nodeID.append(node_id)
                else:
                    logger.info(f'No taints matching with the filter "NoSchedule". Leaving faith in Cluster AutoScaler and not terminating node forcefully')
                    pass
    logger.debug(schedulingDisabled_nodeID)
    return schedulingDisabled_nodeID


def recycle_process(cluster, availability_zone):
    """ Recycle nodes from the availability zone"""
    kubeconfig_context(cluster)
    load_kube_config()
    try:
        nodegroups = eksclient.list_nodegroups(clusterName=cluster)
        if len(nodegroups['nodegroups']) > 0:
            autoscaler_health_check()
            autoscaler_logs(cluster)
            cordon_node(availability_zone)
            drain_affected_node(availability_zone)
            schedulingDisabled_nodes = nodeId_of_schedulingDisabledNode_from_availability_zone(availability_zone)
            for each_nodeId in schedulingDisabled_nodes:
                terminate_node(each_nodeId)
    except Exception as error:
        if '401' in str(error):
            logger.error(f"401 Unauthorized error for cluster '{cluster}'")
        else:
            logger.error(f"The exception is this: {str(error)}")


def main():
    """ Main entry point of the app """
    parser = argparse.ArgumentParser()
    exclusive = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument('--debug', action='store_true', help='Print debug messages to stderr')
    parser.add_argument('--quiet', action='store_true', help='Minimal output')
    parser.add_argument('--az', action='store', help='Specify the availability zone to evacuate')
    parser.add_argument('--cluster', action='store', help='Specify the cluster to perform evacuation process', required=True)
    parser.add_argument('--account', action='store', help='Specify the account name')

    exclusive.add_argument('--capacity', action='store_true', help='Details specific capacity limits and allocation for nodes')
    exclusive.add_argument('--evacuate', action='store_true', help='Evacuate process to drain nodes within specified availability zone')
    exclusive.add_argument('--restore', action='store_true', help='Restoration process to update ASG with all avilability zones')
    exclusive.add_argument('--recycle', action='store_true', help='Recycle process to cordon & drain the node in specific AZ')

    args = parser.parse_args()

    if args.debug:
        logger.setLevel('DEBUG')
    elif args.quiet:
        logger.setLevel('ERROR')
    else:
        logger.setLevel('INFO')
    if args.capacity:
        evacuation_process(
            args.cluster,
            'capacity'
            )
    elif args.evacuate:
        evacuation_process(
            args.cluster,
            'evacuate',
            args.az
            )
    elif args.restore:
            restoration_process(
            args.cluster,
            args.account,
            'restore'
            )
    elif args.recycle:
            recycle_process(
                args.cluster,
                args.az
            )
    else:
        parser.print_help()


if __name__ == "__main__":
    """ This is executed when run from the command line """
    main()
