# K8s-Evacuation-Script

A script designed to make Kubernetes clusters more resilient, automating the cordoning and draining of nodes over to other AZs. The AZ you wish to evacuate can be specified via the CLI argeparse tool integrated.


In the case of an AZ failure, I have implemented a Python script that can be executed from the local machine to mitigate the effects and run an evacuation of the affected availability zone, through the cordoning and draining of nodes sitting within the affected AZ.

Overview
1 - Cluster Capacity Check (informational)
2a - Evacuation
2b - Restoration
3 - Node Recycle

### Overview

AWS rarely have problems which make the entire AZ unusable. During previous outages, the AZ has been degraded and resulted in spurious network and storage errors in the affected availability zone. You may be directed by the AWS Technical Account Manager to leave the AZ.

Based on previous AZ problems, there are 2 ways of mitigating and/or resolving availability zone issues:

1. Completely leave the problematic zone
2. Refresh/recycle all nodes in the affected zones


### Cluster Capacity Check (Informational)

`python3 evacuation.py --cluster <cluster_name>  --capacity --debug`

example:
`python3 evacuation.py --cluster “dev-cluster“  --capacity --debug`

### Evacuation

Specify an Availability Zone to cordon and drain for a specific cluster for evacuation in case of AZ issues within AWS. This process will remove the subnet_id’s those are in the affected AZ from the Auto Scaling Group, Cordon and then drain the nodes in those affected subnet’s . This results in the creation of new nodes in the other available subnet’s.

`python3 evacuation.py --cluster <cluster_name> --AZ <affected_AZ name> --evacuate --debug`

example :
`python3 evacuation.py --cluster “dev-cluster” --AZ “eu-west-2a“ --evacuate --debug`

### Restoration

Restores all availability zones by updating the cluster node autoscaling groups with all subnets. This process will update back the Auto Scaling Group with all the subnet_id’s ( which were present before the evacuation) . This process should be performed once we are sure that the affected AZ is back to normal without any issues.

`python3 evacuation.py --cluster <cluster_name> --account <AWS Account Name> --restore --debug`

example :
`python3 evacuation.py --cluster “dev-cluster“ --account “nbs-eks1-dev“ --restore --debug`

### Node Recycle

We needed the ability to refresh/recycle node on the same AZ to solve the problem which we encountered in the recent past where a specific data centre within AWS AZ was somehow corrupted and we need to recycle the node on that AZ so that it will get created in new hardware within same AZ. This option will cordon, drain and if needed terminate the node from that specific AZ.

`python3 evacuation.py --az <az_name> --cluster <cluster_name> --recycle --debug`

example :
`python3 evacuation.py --az eu-west-2a --cluster shahe-dev --recycle --debug`
