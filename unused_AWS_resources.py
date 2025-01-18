import boto3
import argparse
import csv
import os

from datetime import datetime, timedelta, date, timezone

# CLOUD WATCH LOG GROUPS
def cw_log_group(function, profile_name, unused_resource_count, region_list, account_id, account_name):
    print('Scanning Cloud Watch Log Groups')
    today = date.today()
    file_name = f"unused_resource_logs/{today}_cw_log_groups.csv"

    session = boto3.session.Session(profile_name=profile_name)
    log_group_count = 0
    cw_log_group_detail = []

    for region in region_list:
        try:
            logs = session.client('logs', region_name=region)
            # Paginate through Cloud Watch Log Groups
            paginator = logs.get_paginator('describe_log_groups')
            for page in paginator.paginate():
                log_groups = page.get('logGroups', [])

                for log_group in log_groups:
                    log_group_arn = f"arn:aws:logs:{region}:{account_id}:log-group:{log_group.get('logGroupName', '')}"
                    log_group_name = log_group.get('logGroupName', '')
                    creation_time = log_group.get('creationTime', None)
                    retention_in_days = log_group.get('retentionInDays', 'Never Expire')
                    stored_bytes = log_group.get('storedBytes', 0)

                    cw_log_group_detail.append({
                        'AccountName': account_name,
                        'AccountId': account_id,
                        'ResourceType': 'AWS::SM::LogGroup',
                        'LogGroupArn': log_group_arn,
                        'LogGroupName': log_group_name,
                        'LogGroupCreatedDate': datetime.fromtimestamp(creation_time / 1000, tz=timezone.utc),
                        'RetentionPeriod': retention_in_days,
                        'Size': stored_bytes,
                        'Region': region
                        })
                log_group_count += len(cw_log_group_detail)
                
        except Exception as e:
            print(f"Error scanning Cloud Watch Log Groups in {region}: {e}")
    # Open file in append mode and check if the file already exists
    file_exists = os.path.isfile(file_name)
    with open(file_name, "a", newline='') as csvfile:
        writer =csv.writer(csvfile)
        #Write header ONLY if the file does not already exist
        if not file_exists:
            writer.writerow(["AccountName", "AccountId", "ResourceType", "LogGroupArn", "LogGroupName", "LogGroupCreatedDate", "RetentionPeriod", "Size", "Region"])

    # Write to CSV if any volumes are found
        for cw_log_group_detail in cw_log_group_detail:
            writer.writerow([
                cw_log_group_detail["AccountName"],
                f'="{cw_log_group_detail["AccountId"]}"',
                cw_log_group_detail["ResourceType"],
                cw_log_group_detail["LogGroupArn"],
                cw_log_group_detail["LogGroupName"],
                cw_log_group_detail["LogGroupCreatedDate"],
                cw_log_group_detail["RetentionPeriod"],
                cw_log_group_detail["Size"],
                cw_log_group_detail["Region"]
                        ])

    unused_resource_count[function] = log_group_count
    
    # Notify if there are no Cloud Watch Log Groups
    if log_group_count == 0:
        print("No Cloud Watch Log Groups to Report")
    else:
        print("Cloud Watch Log Group Count: ", unused_resource_count)

# EBS VOLUMES
def ebs_volume(function, profile_name, unused_resource_count, region_list, account_id, account_name):
    print('Scanning EBS Volumes')
    today = date.today()
    file_name = f"unused_resource_logs/{today}_ebs_volume.csv"

    session = boto3.session.Session(profile_name=profile_name)
    volume_count = 0
    unused_volume_detail = []

    for region in region_list:
        try:
            ec2 = session.client('ec2', region_name=region)
            # Paginate through EBS Volumes
            paginator = ec2.get_paginator('describe_volumes')
            for page in paginator.paginate():
                volumes = page.get('Volumes', [])

                for volume in volumes:
                    if volume['State'] == 'available':
                        unused_volume_detail.append({
                            'AccountName': account_name,
                            'AccountId': account_id,
                            'ResourceType': 'AWS::EC2::Volume',
                            'ResourceId': volume['VolumeId'],
                            'State': volume['State'],
                            'Region': region
                        })
                volume_count += len(unused_volume_detail)
                
        except Exception as e:
            print(f"Error scanning EBS volumes in {region}: {e}")
    # Open file in append mode and check if the file already exists
    file_exists = os.path.isfile(file_name)
    with open(file_name, "a", newline='') as csvfile:
        writer =csv.writer(csvfile)
        #Write header ONLY if the file does not already exist
        if not file_exists:
            writer.writerow(["AccountName", "AccountId", "ResourceType", "ResourceId", "State", "Region"])

    # Write to CSV if any volumes are found
        for unused_volume_detail in unused_volume_detail:
            writer.writerow([
                unused_volume_detail[["AccountName"]],
                f'="{unused_volume_detail["AccountId"]}"',
                unused_volume_detail["ResourceType"],
                unused_volume_detail["ResourceId"],
                unused_volume_detail["State"],
                unused_volume_detail["Region"]
                        ])

    unused_resource_count[function] = volume_count
    
    # Notify if there are no EBS volumes
    if volume_count == 0:
        print("No Unused EBS Volumes to Report")
    else:
        print("Volume Count: ", unused_resource_count)

# ELASTIC IPs
def elastic_ip(function, profile_name, unused_resource_count, region_list, account_id, account_name):
    print('Scanning Elastic IPs')
    today = date.today()
    file_name = f"unused_resource_logs/{today}_elastic_ip.csv"

    session = boto3.session.Session(profile_name=profile_name)
    eip_count = 0
    unused_eip_detail = []
    
    for region in region_list:
        try:
            ec2 = session.client('ec2',region_name=region)
            
            paginator = ec2.get_paginator('describe_addresses')
            page_iterator = paginator.paginate()
            for page in page_iterator:
                eip_data = page.get('Addresses', [])
                for eip in eip_data:
                    AssociationId = eip.get('AssociationId', '')
                    if not AssociationId:
                        unused_eip_detail.append({
                            'AccountName': account_name,
                            'AccountId': account_id,
                            'ResourceType': 'AWS::EC2::EIP',
                            'ResourceId': eip['AllocationId'],
                            'AssociationId': AssociationId,
                            'Region': region
                        })
                        eip_count += len(unused_eip_detail)
        except Exception as e:
            print(f"Error scanning Elastic IPs in {region}: {e}")

    # Open file in append mode and check if the file already exists
    file_exists = os.path.isfile(file_name)
    with open(file_name, "a", newline='') as csvfile:
        writer =csv.writer(csvfile)
        #Write header ONLY if the file does not already exist
        if not file_exists:
            writer.writerow(["AccountName", "AccountId", "ResourceType", "ResourceId", "AssociationId", "Region"])

        # Write results to file
        for unused_eip_detail in unused_eip_detail:
            writer.writerow([
                unused_eip_detail["AccountName"],
                f'="{unused_eip_detail["AccountId"]}"',
                unused_eip_detail["ResourceType"],
                unused_eip_detail["ResourceId"],
                unused_eip_detail["AssociationId"],
                unused_eip_detail["Region"]
                ])

    unused_resource_count[function] = eip_count

    # Notify if there are no unused Elastic IPs
    if eip_count == 0:
        print("No Unused Elastic IPs to Report")
    else:
        print("Unused Elastic IP Count: ", unused_resource_count)

# NETWORK INTERFACES
def network_interface(function, profile_name, unused_resource_count, region_list, account_id, account_name):
    print('Scanning Network Interfaces')
    today = date.today()
    file_name = f"unused_resource_logs/{today}_network_interface.csv"

    session = boto3.session.Session(profile_name=profile_name)
    ni_count = 0
    unused_ni_detail = []

    for region in region_list:
        try:
            ec2 = session.client('ec2', region_name=region)
            paginator = ec2.get_paginator('desribe_network_interfaces')
            page_iterator = paginator.paginate()
            for page in page_iterator:
                # Fetch paginated results for network interfaces
                network_interfaces = page.get('NetworkInterfaces', [])
                for network_interface in network_interfaces:
                    if network_interface['Status'] == 'available':
                        unused_ni_detail.append({
                            'AccountName': account_name,
                            'AccountId': account_id,
                            'ResourceType': 'AWS::EC2::NetworkInterface',
                            'ResourceId': network_interface['NetworkInterfaceId'],
                            'Status': network_interface['Status'],
                            'Region': region
                        })
                ni_count += len(unused_ni_detail)

        except Exception as e:
            print(f"Error scanning Network Interfaces in {region}: {e}")

    # Open file in append mode and check if the file already exists
    file_exists = os.path.isfile(file_name)
    with open(file_name, "a", newline='') as csvfile:
        writer =csv.writer(csvfile)
        #Write header ONLY if the file does not already exist
        if not file_exists:
            writer.writerow(["AccountName", "AccountId", "ResourceType", "ResourceId", "Status", "Region"])

        # Write results to file
        for unused_ni_detail in unused_ni_detail:
            writer.writerow([
                unused_ni_detail["AccountName"],
                f'="{unused_ni_detail["AccountId"]}"',
                unused_ni_detail["ResourceType"],
                unused_ni_detail["ResourceId"],
                unused_ni_detail["Status"],
                unused_ni_detail["Region"]
                ])

    unused_resource_count[function] = ni_count
    if ni_count == 0:
        print("No Unused Network Interfaces to Report")
    else:
        print("Unused Network Interface Count: ", unused_resource_count)

# VPCs
def vpc(function, profile_name, unused_resource_count, region_list, account_id, account_name):
    print('Scanning VPCs')
    today = date.today()
    file_name = f"unused_resource_logs/{today}_vpc.csv"

    session = boto3.session.Session(profile_name=profile_name)
    vpc_count = 0
    unused_vpc_detail = []

    for region in region_list:
        try:
            ec2 = session.client('ec2', region_name=region)
            #Paginate through VPCs
            vpcs = []
            paginator_vpcs = ec2.get_paginator('describe_vpcs')
            for page in paginator_vpcs.paginate():
                vpcs.extend(page.get('Vpcs', []))
            #Paginate through Network Interfaces
            paginator_network_interfaces = ec2.get_paginator('describe_network_interfaces')
            network_interfaces = []
            for page in paginator_network_interfaces.paginate():
                network_interfaces.extend(page.get('NetworkInterfaces', []))

            # Calculate unused VPCs
            all_vpcs = set([vpc['VpcId'] for vpc in vpcs])
            all_active_vpcs = set([ni['VpcId'] for ni in network_interfaces])
            unused_vpcs = all_vpcs - all_active_vpcs
            for vpcid in unused_vpcs:
                unused_vpc_detail.append({
                    'AccountName': account_name,
                    'AccountId': account_id,
                    'ResourceType': 'AWS::EC2::VPC',
                    'ResourceId': vpcid,
                    'ReasonClassifiedAsUnused': 'Not associated with any Network Interface',
                    'Region': region
                })
            vpc_count += len(unused_vpc_detail)

        except Exception as e:
            print(f"Error scanning VPCs in {region}: {e}")

    # Open file in append mode and check if the file already exists
    file_exists = os.path.isfile(file_name)
    with open(file_name, "a", newline='') as csvfile:
        writer =csv.writer(csvfile)
        #Write header ONLY if the file does not already exist
        if not file_exists:
            writer.writerow(["AccountName", "AccountId", "ResourceType", "ResourceId", "ReasonClassifiedAsUnused", "Region"])

        # Write results to file
        for unused_vpc_detail in unused_vpc_detail:
            writer.writerow([
                unused_vpc_detail["AccountName"],
                f'="{unused_vpc_detail["AccountId"]}"',
                unused_vpc_detail["ResourceType"],
                unused_vpc_detail["ResourceId"],
                unused_vpc_detail["ReasonClassifiedAsUnused"],
                unused_vpc_detail["Region"]
                ])

    unused_resource_count[function] = vpc_count
    if vpc_count == 0:
        print("No Unused VPCs to Report")
    else:
        print("Unused VPC Count: ", unused_resource_count)

# SUBNETS
def subnet(function, profile_name, unused_resource_count, region_list, account_id, account_name):
    print('Scanning Subnets')
    today = date.today()
    file_name = f"unused_resource_logs/{today}_subnet.csv"

    session = boto3.session.Session(profile_name=profile_name)
    subnet_count = 0
    unused_subnet_detail = []

    for region in region_list:
        try:
            ec2 = session.client('ec2', region_name=region)
            # Paginate through Subnets
            subnets = []
            paginator_subnets = ec2.get_paginator('describe_subnets')
            for page in paginator_subnets.paginate():
                subnets.extend(page.get('Subnets', []))
            # Paginate throuhg Network Interfaces
            network_interfaces = []
            paginator_network_interfaces = ec2.get_paginator('describe_network_interfaces')
            network_interfaces = []
            for page in paginator_network_interfaces.paginate():
                network_interfaces.extend(page.get('NetworkInterfaces', []))

            # Calculate unused Subnets as those without associated network interfaces
            all_subnets = set([subnet['SubnetId'] for subnet in subnets])
            all_active_subnets = set([ni['SubnetId'] for ni in network_interfaces])
            unused_subnets = all_subnets - all_active_subnets
            for subnet_id in unused_subnets:
                unused_subnet_detail.append({
                    'AccountName': account_name,
                    'AccountId': account_id,
                    'ResourceType': 'AWS::EC2::Subnet',
                    'ResourceId': subnet_id,
                    'ReasonClassifiedAsUnused': 'Not associated with any Network Interface',
                    'Region': region
                })
            subnet_count += len(unused_subnet_detail)
        except Exception as e:
            print(f"Error scanning Subnets in {region}: {e}")

    # Open file in append mode and check if the file already exists
    file_exists = os.path.isfile(file_name)
    with open(file_name, "a", newline='') as csvfile:
        writer =csv.writer(csvfile)
        #Write header ONLY if the file does not already exist
        if not file_exists:
            writer.writerow(["AccountName", "AccountId", "ResourceType", "ResourceId", "ReasonClassifiedAsUnused", "Region"])

        # Write results to file
        for unused_subnet_detail in unused_subnet_detail:
            writer.writerow([
                unused_subnet_detail["AccountName"],
                f'="{unused_subnet_detail["AccountId"]}"',
                unused_subnet_detail["ResourceType"],
                unused_subnet_detail["ResourceId"],
                unused_subnet_detail["ReasonClassifiedAsUnused"],
                unused_subnet_detail["Region"]
                ])

    unused_resource_count[function] = subnet_count
    if subnet_count == 0:
        print("No Unused Subnets to Report")
    else:
        print("Unused Subnet Count: ", unused_resource_count)

# SECURITY GROUPS
def security_group(function, profile_name, unused_resource_count, region_list, account_id, account_name):
    print('Scanning Security Groups')
    today = date.today()
    file_name = f"unused_resource_logs/{today}_security_group.csv"

    session = boto3.session.Session(profile_name=profile_name)
    sg_count = 0
    unused_sg_detail = []
    
    for region in region_list:
        try:
            ec2 = session.client('ec2', region_name=region)
            # Paginate through Security Groups
            security_groups = []
            paginator_security_groups = ec2.get_paginator('describe_secuirty_groups')
            for page in paginator_security_groups.paginate():
                security_groups.extend(page.get('SecurityGroups', []))
            # Paginate through Network Interfaces
            network_interfaces = []
            paginator_network_interfaces = ec2.get_paginator('describe_network_interfaces')
            for page in paginator_network_interfaces.paginate():
                network_interfaces.extend(page.get('NetworkInterfaces', []))

            all_sgs = set([sg['GroupId'] for sg in security_groups])
            all_inst_sgs = set([sg['GroupId'] for ni in network_interfaces for sg in ni['Groups']])
            # Calculate unused Security Groups as those not associated with any network interfaces
            unused_sgs = all_sgs - all_inst_sgs
            for sgid in unused_sgs:
                unused_sg_detail.append({
                    'AccountName': account_name,
                    'AccountId': account_id,
                    'ResourceType': 'AWS::EC2::SecurityGroup',
                    'ResourceId': sgid,
                    'ReasonClassifiedAsUnused': 'Not associated with any Network Interface',
                    'Region': region
                })
            sg_count += len(unused_sg_detail)
        except Exception as e:
            print(f"Error scanning Security Groups in {region}: {e}")

    # Open file in append mode and check if the file already exists
    file_exists = os.path.isfile(file_name)
    with open(file_name, "a", newline='') as csvfile:
        writer =csv.writer(csvfile)
        #Write header ONLY if the file does not already exist
        if not file_exists:
            writer.writerow(["AccountName", "AccountId", "ResourceType", "ResourceId", "ReasonClassifiedAsUnused", "Region"])

        # Write results to file
        for unused_sg_detail in unused_sg_detail:
            writer.writerow([
                unused_sg_detail["AccountName"],
                f'="{unused_sg_detail["AccountId"]}"',
                unused_sg_detail["ResourceType"],
                unused_sg_detail["ResourceId"],
                unused_sg_detail["ReasonClassifiedAsUnused"],
                unused_sg_detail["Region"]
                ])

    unused_resource_count[function] = sg_count
    if sg_count == 0:
        print("No Unused Security Groups to Report")
    else:
        print("Unused Security Group Count: ", unused_resource_count)

# CLASSIC LOAD BALANCERS
def classic_loadbalancer(function, profile_name, unused_resource_count, region_list, account_id, account_name):
    print('Scanning Classic Load balancers')
    today = date.today()
    file_name = f"unused_resource_logs/{today}_classic_loadbalancer.csv"

    session = boto3.session.Session(profile_name=profile_name)
    elb_count = 0
    unused_elb_detail = []
    
    for region in region_list:
        try:
            ec2 = session.client('elb', region_name=region)
            # Paginate through Load Balancers
            load_balancers = []
            paginator = ec2.get_paginator('describe_load_balancers')
            for page in paginator.paginate():
                load_balancers = page.get('LoadBalancerDescriptions', [])


            for elb_detail in load_balancers:
                load_balancer_name = elb_detail['LoadBalancerName']
                # Retrieve instance health status
                instance_health_response = ec2.describe_instance_health(LoadBalancerName=load_balancer_name)
                instance_states = {instance['InstanceId']: instance['State'] for instance in instance_health_response['InstanceStates']}
                # Mark unused if no instances are in "InService" state
                if all(state != 'InService' for state in instance_states.values()):
                    unused_elb_detail.append({
                        'AccountName': account_name,
                        'AccountId': account_id,
                        'ResourceType': 'AWS::ElasticLoadBalancing::LoadBalancer',
                        'ResourceId': elb_detail['LoadBalancerName'],
                        'InstanceStates': instance_states,
                        'Region': region
                    })
                    elb_count += 1
        except Exception as e:
            print(f"Error scanning Classic Load Balancers in {region}: {e}")

    # Open file in append mode and check if the file already exists
    file_exists = os.path.isfile(file_name)
    with open(file_name, "a", newline='') as csvfile:
        writer =csv.writer(csvfile)
        #Write header ONLY if the file does not already exist
        if not file_exists:
            writer.writerow(["AccountName", "AccountId", "ResourceType", "ResourceId", "InstanceStates", "Region"])

        # Write results to file
        for unused_elb_detail in unused_elb_detail:
            writer.writerow([
                unused_elb_detail["AccountName"],
                f'="{unused_elb_detail["AccountId"]}"',
                unused_elb_detail["ResourceType"],
                unused_elb_detail["ResourceId"],
                unused_elb_detail["InstanceStates"],
                unused_elb_detail["Region"]
                ])

    unused_resource_count[function] = elb_count
    if elb_count == 0:
        print("No Unused Classic Load Balancers to Report")
    else:
        print("Unused Classic Load Balancer Count: ", unused_resource_count)

#  APPLICATION NETWORK GATEWAY LOAD BALANCERS
def app_nw_gateway_loadbalancer(function, profile_name, unused_resource_count, region_list, account_id, account_name):
    print('Scanning Application/Network/Gateway Load balancers')
    today = date.today()
    file_name = f"unused_resource_logs/{today}_app_nw_gateway_loadbalancer.csv"

    session = boto3.session.Session(profile_name=profile_name)
    elbv2_count = 0
    unused_elbv2_detail = []
    
    for region in region_list:
        try:
            elbv2 = session.client('elbv2', region_name=region)
            
            # Paginate through app_nw_gateway_loadbalancers
            paginator = elbv2.get_paginator('describe_load_balancers')
            for page in paginator.paginate():
                load_balancers = page.get('LoadBalancers', [])


                for elbv2_detail in load_balancers:
                    target_health_status = []
                    try:
                        target_group_detail = elbv2.describe_target_groups(LoadBalancerArn=elbv2_detail['LoadBalancerArn'])['TargetGroups']
                        for target_group in target_group_detail:
                            target_group_health = elbv2.describe_target_health(TargetGroupArn=target_group['TargetGroupArn'])['TargetHealthDescriptions']
                            for target in target_group_health:
                                target_health_status.append(target['TargetHealth']['State'])
                    except Exception as e:
                        print(f"Error retrieving target group details for {elbv2_detail['LoadBalancerName']}: {e}")
                    if 'healthy' not in target_health_status:
                        unused_elbv2_detail.append({
                            'AccountName': account_name,
                            'AccountId': account_id,
                            'ResourceType': 'AWS::ElasticLoadBalancingV2::LoadBalancer',
                            'LoadBalancer_Type': elbv2_detail['Type'],
                            'ResourceId': elbv2_detail['LoadBalancerName'],
                            'Target': target_group.get('TargetGroupName', 'N/A'),
                            'TargetHealthStatus': target_health_status,
                            'Region': region
                        })
                        elbv2_count += len(unused_elbv2_detail)

        except Exception as e:
            print(f"Error scanning Netowrk Gateway Load Balancers in {region}: {e}")

    # Open file in append mode and check if the file already exists
    file_exists = os.path.isfile(file_name)
    with open(file_name, "a", newline='') as csvfile:
        writer =csv.writer(csvfile)
        #Write header ONLY if the file does not already exist
        if not file_exists:
            writer.writerow(["AccountName", "AccountId", "ResourceType", "ResourceId", "Target", "TargetHealthStatus", "Region"])

        # Write results to file
        for unused_elbv2_detail in unused_elbv2_detail:
            writer.writerow([
                unused_elbv2_detail["AccountName"],
                f'="{unused_elbv2_detail["AccountId"]}"',
                unused_elbv2_detail["ResourceType"],
                unused_elbv2_detail["LoadBalancer_Type"],
                unused_elbv2_detail["ResourceId"],
                unused_elbv2_detail["Target"],
                unused_elbv2_detail["TargetHealthStatus"],
                unused_elbv2_detail["Region"]
                ])

    unused_resource_count[function] = elbv2_count
    if elbv2_count == 0:
        print("No Unused Application/Network/Gateway Load Balancers to Report")
    else:
        print("Application/Network/Gateway Load Balancers Count: ", unused_resource_count)

# IAM USERS
def iam_user(function, profile_name, unused_resource_count, region_list, account_id, account_name):
    print('Scanning IAM Users')
    #Create file
    today = date.today()
    file_name = f"unused_resource_logs/{today}_iam_user.csv"
    #Set up IAM client
    session = boto3.session.Session(profile_name=profile_name)
    iam = session.resource('iam')  
    iam_client = session.client('iam')
    #Set variables
    iamuser_count = 0
    inactive_threshold = datetime.now(timezone.utc) - timedelta(days=180)
    unused_iamuser_detail = []

    try:
        # Paginate through IAM users
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            users = page.get('Users', [])

            for user in users:
                username = user['UserName']
                password_last_used = user.get('PasswordLastUsed')  # Retrieve 'PasswordLastUsed' if available
                last_activity = password_last_used  # Initialize 'last_activity' with 'PasswordLastUsed'
                # Check access key last used
                access_keys = iam_client.list_access_keys(UserName=username)
                for key in access_keys['AccessKeyMetadata']:
                    key_id = key['AccessKeyId']
                    key_last_used = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                    if 'LastUsedDate' in key_last_used['AccessKeyLastUsed']:
                        key_last_used_date = key_last_used['AccessKeyLastUsed']['LastUsedDate']
                        # Update 'last_activity' if access key was used more recently than password
                        if not last_activity or key_last_used_date > last_activity:
                            last_activity = key_last_used_date
                # Determine if the user is inactive
                if not last_activity or last_activity < inactive_threshold:
                    unused_iamuser_detail.append({
                        'AccountName': account_name,
                        'AccountId': account_id,
                        'ResourceType': 'AWS::IAM::User',
                        'UserName': username,
                        'LastActivity': last_activity.strftime('%Y-%m-%d') if last_activity else 'Never Active'
                    })
                    iamuser_count += len(unused_iamuser_detail)

    except Exception as e:
        print(f"Error processing IAM user details: {e}")

    # Open file in append mode and check if the file already exists
    file_exists = os.path.isfile(file_name)
    with open(file_name, "a", newline='') as csvfile:
        writer =csv.writer(csvfile)
        #Write header ONLY if the file does not already exist
        if not file_exists:
            writer.writerow(["AccountName", "AccountId", "ResourceType", "UserName", "LastActivity"])

        # Write results to file

    # Write inactive IAM users to CSV
        for unused_iamuser_detail in unused_iamuser_detail:
            writer.writerow([
                unused_iamuser_detail["AccountName"],
                f'="{unused_iamuser_detail["AccountId"]}"',
                unused_iamuser_detail["ResourceType"],
                unused_iamuser_detail["UserName"],
                unused_iamuser_detail["LastActivity"]
                ])

    unused_resource_count[function] = iamuser_count
    if iamuser_count == 0:
        print("No Unused IAM Users to Report")
    else:
        print("Unused IAM Users Count", unused_resource_count)

# IAM GROUPS
def iam_group(function, profile_name, unused_resource_count, region_list, account_id, account_name):
    print('Scanning IAM Groups')
    today = date.today()
    file_name = f"unused_resource_logs/{today}_iam_group.csv"

    session = boto3.session.Session(profile_name=profile_name)
    iamgroup_count = 0
    unused_iamgroup_detail = []

    try:
        iam_client = session.client('iam')
        # Paginate through IAM Groups
        paginator = iam_client.get_paginator('list_groups')
        for page in paginator.paginate():
            groups = page.get('Groups', [])

            for group in groups:
                group_name = group['GroupName']
                try:
                    if not iam_client.get_group(GroupName=group_name)['Users']:
                        unused_iamgroup_detail.append({
                            'AccountName': account_name,
                            'AccountId': account_id,
                            'ResourceType': 'AWS::IAM::GROUP',
                            'ResourceId': group_name,
                            'ReasonClassifiedAsUnused': 'No Users within Group',
                            'Region': 'Global'
                        })
                except Exception as e:
                    print(f"Error retrieving users for group {group_name}: {e}")
        iamgroup_count += len(unused_iamgroup_detail)

    except Exception as e:
        print(f"Error scanning IAM Groups: {e}")

    # Open file in append mode and check if the file already exists
    file_exists = os.path.isfile(file_name)
    with open(file_name, "a", newline='') as csvfile:
        writer =csv.writer(csvfile)
        #Write header ONLY if the file does not already exist
        if not file_exists:
            writer.writerow(["AccountName", "AccountId", "ResourceType", "ResourceId", "ReasonClassifiedAsUnused", "Region"])

        # Write results to file
        for unused_iamgroup_detail in unused_iamgroup_detail:
            writer.writerow([
                unused_iamgroup_detail["AccountName"],
                f'="{unused_iamgroup_detail["AccountId"]}"',
                unused_iamgroup_detail["ResourceType"],
                unused_iamgroup_detail["ResourceId"],
                unused_iamgroup_detail["ReasonClassifiedAsUnused"],
                unused_iamgroup_detail["Region"]
                ])

    unused_resource_count[function] = iamgroup_count
    if iamgroup_count == 0:
        print("No Unused IAM Groups to Report")
    else:
        print("Unused IAM Group Count: ", unused_resource_count)

def load_profiles_from_csv(csv_file="profiles.csv"):
    profiles = []
    try:
        with open(csv_file, mode="r") as file:
            reader = csv.DictReader(file)
            print("CSV Headers:", reader.fieldnames) # Print headers for debugging
            for row in reader:
                profiles.append(row["profile_name"])
    except FileNotFoundError:
        print(f"CSV File '{csv_file}' not found.")
    except KeyError:
        print("The CSV file must contain a 'profile_name' column.")

    return profiles

def get_account_name(profile_name):
    # Initialize the session with a specific profile
    session = boto3.Session(profile_name=profile_name)
    sts_client = session.client('sts')
    account_id = sts_client.get_caller_identity()["Account"]

    try:
        # Get the account ID of the current session
        organizations_client = session.client('organizations')

        # Use the Organizations client to describe the account
        response = organizations_client.describe_account(AccountId=account_id)
        account_name = response['Account']['Name']
        print(f"Account Name: {account_name}")
        return account_name
    except organizations_client.exceptions.AccessDeniedException:
        print("Access denied to AWS Organization API. Returning manual name assignment.")
        if profile_name == "associa-admin-qa":
            manual_account_name = "Associa Dev/QA"
        if profile_name == "associa-it-admin":
            manual_account_name = "Associa IT Ops"
        if profile_name == "associa-admin-prod":
            manual_account_name = "Associa Prod"
        if profile_name == "associa-admin-uat":
            manual_account_name = "Associa UAT"
        if profile_name == "associa-admin-billing":
            manual_account_name = "Associa Billing"
        if profile_name == "associa-admin-dev":
            manual_account_name = "Associa Dev"
        if profile_name == "atg-admin-prod":
            manual_account_name = "ATG Prod"
        if profile_name == "atg-admin-qa":
            manual_account_name = "ATG QA"
        if profile_name == "atg-admin-uat":
            manual_account_name = "ATG UAT"
        if profile_name == "audit-admin":
            manual_account_name = "Audit"
        if profile_name == "ca-admin-qa":
            manual_account_name = "CA Dev/QA"
        if profile_name == "ca-admin-prod":
            manual_account_name = "CA Prod"
        if profile_name == "ca-admin-uat":
            manual_account_name = "CA UAT"
        if profile_name == "cm4-admin-prod":
            manual_account_name = "CM4 Prod"
        if profile_name == "cm4-admin-qa":
            manual_account_name = "CM4 QA"
        if profile_name == "cm4-admin-uat":
            manual_account_name = "CM4 UAT"
        if profile_name == "inspireflex-admin-dev":
            manual_account_name = "InspireFlex Dev"
        if profile_name == "inspireflex-admin-prod":
            manual_account_name = "InspireFlex Prod"
        if profile_name == "logarchive-admin":
            manual_account_name = "Log Archive"
        if profile_name == "tsq-dl-admin-dev":
            manual_account_name = "TownSq Data Lake Dev"
        if profile_name == "tsq-dl-admin-prod-br":
            manual_account_name = "TownSq Data Lake Prod BR"
        if profile_name == "tsq-dl-admin-prod-us":
            manual_account_name = "TownSq Data Lake Prod US"
        if profile_name == "tsq-dl-analytics-admin":
            manual_account_name =  "TownSq Data Lake Analytics"
        if profile_name == "townsq-admin-prod-br":
            manual_account_name = "TownSq Prod BR"
        if profile_name == "townsq-admin-prod-us":
            manual_account_name = "TownSq Prod US"
        if profile_name == "townsq-admin-qa":
            manual_account_name = "TownSq QA"
        if profile_name == "townsq-shared-admin":
            manual_account_name = "TownSq Shared"
        if profile_name == "townsq-admin-uat":
            manual_account_name = "TownSq UAT"
        return manual_account_name
    
    except Exception as e:
        print(f"Error retrieving account name: {e}")

def main(args):
    # Load profiles from CSV
    profiles = load_profiles_from_csv(args.csv_file) if args.csv_file else load_profiles_from_csv()

    if not profiles:
        print("No profiles found in the CSV file.")
        return
    
    # Map function names to function objects

    function_mapping = {
        "ebs_volume": ebs_volume,
        "elastic_ip": elastic_ip,
        "network_interface": network_interface,
        "vpc": vpc,
        "subnet": subnet,
        "security_group": security_group,
        "classic_loadbalancer": classic_loadbalancer,
        "app_nw_gateway_loadbalancer": app_nw_gateway_loadbalancer,
        "iam_user": iam_user,
        "iam_group": iam_group,
        "cw_log_group": cw_log_group
    }

    if args.function and args.function not in function_mapping:
        print(f"Invalid function name: {args.function}")
        print(f"Available functions: {', '.join(function_mapping.keys())}")

    for profile_name in profiles:
        print(f"\nProcessing profile: {profile_name}")
        try:
            # Initialize a session for the current profile
            session = boto3.session.Session(profile_name=profile_name)
            sts = session.client("sts")
            account_id = sts.get_caller_identity()["Account"]
            account_name = get_account_name(profile_name)
            print(f"Connected to account: {account_name} {account_id}")

            # Get the list of enabled regions for this account
            ec2 = session.client('ec2', region_name="us-east-1")
            region_list = [region['RegionName'] for region in ec2.describe_regions()['Regions']]

            # Dictionary to store the resource count for each function
            unused_resource_count = {}

            # Run a single function
            if args.function:
                function = function_mapping[args.function]
                function(function, profile_name, unused_resource_count, region_list, account_id, account_name)
            else:
                # Run all functions if no function is provided
                for function in function_mapping.values():
                    function(function, profile_name, unused_resource_count, region_list, account_id, account_name)

            print(f"Completed processing for profile: {profile_name}")

        except Exception as e:
            print(f"Error processing profile {profile_name}: {e}")

    print("\nAll profiles processed successfully.")

if(__name__ == '__main__'):
    arg_parser = argparse.ArgumentParser(
        prog='unused_aws_resources',
        usage='%(prog)s [options]',
        description='Scan AWS accounts for unused resources'
        )
    
    # Optional argument to specify the CSV file for profiles
    arg_parser.add_argument(
        '--csv-file',
        type=str,
        default='profiles.csv',
        help='Path to the CSV file containing AWS profile names.'
        ) 
    
    # Optional argument to specify a single function to run
    arg_parser.add_argument(
        '--function',
        type=str,
        help='Name of the function to run (ebs_volume, elastic_ip, network_interface, vpc, subnet, security_group, classic_loadbalancer, app_nw_gateway_loadbalancer, iam_user, iam_group, cw_log_group).'
        )
    # Parse arguments and run main
    args = arg_parser.parse_args() 
    main(args)
