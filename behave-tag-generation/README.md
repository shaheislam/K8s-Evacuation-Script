# Behave-Tag-Generation Script

A script designed to capture feature flags which have been set for a Kubernetes cluster using multiple modules within Terraform. These feature flags have corresponding tags associated with them in `behave_tags.json`, which are then appended and get into a Behave Testing suite.

The logic for this is quite complicated however I refined the code down to make the solution quite elegant.

### Points of Note

1. Line 126 `for line in cluster_tfvars + account_tfvars + global_tfvars:` is a simple yet effective way to prioritise cluster_tfvars > account_tfvars > global_tfvars, taking into account the override capabilities of Terraform.
2. `feature on` and `feature off` accomodate multpiple feature flags to a single Behave tag, adding flexibility and mitigates repeated testing.
