# unused_AWS_resources_python
List of functions for various AWS resources that creates a CSV of unused resources based on specific criteria.

"""
SYNOPSIS
--------
    Get the details of unused resources present across regions in the AWS account
DESCRIPTION
-----------
    This script provides a detailed overview of the number of unused resources present in the AWS account.
    It provides service-wise details of various unused resources lying around in all the regions of the AWS account.
PREREQUISITES
-------------
        -   Workstation with Python version 3 and above
            Installation command(s):
            - pip3 install boto3
        -   User session of a user having at least the Security Audit permission and above on the AWS account
            - Please login to your AWS SSO profile prior to running the script
        -   File titled "profiles.csv" with header "profile_name" and list of all desired AWS account SSO profile names
        -   Folder titled "unused_resource_logs"
EXAMPLE
-------
    This script can be executed on a python compiler (AWS Cloudshell, Powershell, bash, any command line tool with python installed such as VisualStudio)
    NOTE: If you do not specify a function the script will run ALL functions.
    Command:
python ./unused_aws_resources.py --function (Name of the function you wish to run: ebs_volume, elastic_ip, network_interface, vpc, subnet, security_group, classic_loadbalancer, app_nw_gateway_loadbalancer, iam_user, iam_group, cw_log_group).'
    
OUTPUT
------
    - The script will provide a summarized count of all unused resources in the account.
    - For a detailed view, the user can refer to the .csv files that will be generated by the script for each resource within the unused_resource_logs folder. They are organized by date.
"""
