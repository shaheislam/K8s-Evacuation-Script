#!/usr/bin/env python3
# pylint: disable=W1203,E1205,C0301,C0103,C0115,W1401
import json
import re
import sys

TF_MODULE_PATH = sys.argv[1]
MODULE_NAME = TF_MODULE_PATH.split('/')[-1]
ACCOUNT_NAME = sys.argv[2]
CLUSTER_NAME = sys.argv[3]

tags = ''
test_prefix = '@eks.'

data = json.load(open('scripts/behave_tags.json'))

cluster_tfvars = open("org/" + ACCOUNT_NAME + "/" + CLUSTER_NAME + "/terraform.tfvars", "r").readlines()
account_tfvars = open("org/" + ACCOUNT_NAME + "/terraform.tfvars", "r").readlines()
global_tfvars = open("org/terraform.tfvars", "r").readlines()


def base0_to_base1(base0):
    """Convert a list of indices starting at 0 to starting at 1"""
    return [base + 1 for base in base0]


class HCLVarFile:
    """Open and work with a HCL variable file, borrowed from epaas-chart-bakery"""
    def __init__(self, filename):
        """Init function"""
        self.parse_hcl_file(filename)
        self.variable = {}
        self.filename = filename
        self.touched = False

    def parse_hcl_file(self, filename):
        """Load a HCL file"""
        # logger.info(f"Reading HCL file '{filename}'")
        with open(filename, "r") as myfile:
            self.fullfile = myfile.readlines()

    def get_default(self, varname):
        """Locate a variable and return a reference to it"""
        # simple parser for variable files
        start_marker_str = f"^variable\s*\\\"{varname}\\\"\s*{{"
        end_marker = re.compile("^\s*}")
        start_marker = re.compile(start_marker_str)
        # set some defaults
        matches = []
        tail_braces = []
        dvalue = None
        location = None
        string_start = None
        start = None
        end = None
        # Scan our file for matching starts and any closing braces
        for index, rowstring in enumerate(self.fullfile):
            if start_marker.match(rowstring):
                matches.append(index)
            if end_marker.match(rowstring):
                tail_braces.append(index)
        # check our results
        if matches:
            if len(matches) > 1:
                raise Exception(
                    f"matching of variable {varname} ambiguous - found matches at lines {base0_to_base1(matches)} "
                )
            else:
                start = matches[0]
                if len(tail_braces) > 0:
                    if tail_braces[-1] > start:
                        end = [brace for brace in tail_braces if brace > start][0] + 1
                    else:
                        raise Exception(f"Could not find closing brace for variable {varname}.")
                else:
                    raise Exception("Could not find closing braces.")
        else:
            # logger.info(f'Could not find {varname}')
            pass
        if start and end:
            for index, rowstring in enumerate(self.fullfile[start:end]):
                result = re.search('\s*default\s*=\s*(?:"|)(.+?)(?:"|)', rowstring)
                if result:
                    string_start = result.start(1)
                    dvalue = result.group(1)
                    location = start + index
                    if dvalue[0] == '"' and dvalue[-1] == '"':
                        dvalue = result[1:-1]
        # store the variable details in our attributes for use later
        self.variable[varname] = {
            "slice": slice(start, end, 1),
            "value_location": string_start,
            "line_location": location,
            "value": dvalue
        }
        return self.variable[varname]["value"]


def feature_on(line, value):
    return (
        (isinstance(value, list) and any(re.match(f'^\s*{index}\s*=\s*(1|true)', line) for index in value)) or
        (isinstance(value, str) and value in line)
    ) and re.match(f'^\s*{value}\s*=\s*(1|true)', line)


def feature_off(line, value):
    return (
        (isinstance(value, list) and any(re.match(f'^\s*{index}\s*=\s*(0|false)', line) for index in value)) or
        (isinstance(value, str) and value in line)
    ) and re.match(f'^\s*{value}\s*=\s*(0|false)', line)


default_variables = HCLVarFile(f'{TF_MODULE_PATH}/variables.tf')

if MODULE_NAME == 'infra':
    module = data['infra']
else:
    module = data['apps']

for key, value in module.items():
    if value == 1:
        tags += test_prefix + key + ','
    else:
        # first get the value from variables.tf
        default_value = bool(int(default_variables.get_default(value)))
        for line in cluster_tfvars + account_tfvars + global_tfvars:
            # dis- or en-able features with override from tfvars
            if feature_on(line, value):
                default_value = True
                break
            elif feature_off(line, value):
                default_value = False
                break
        if default_value:
            tags += test_prefix + key + ','

result = tags.rstrip(',')
print(result)
