#!/usr/bin/env python3
"""
AWS WAF Rule Group Exporter & Importer
Export rules from a WAF rule group to JSON and create new rule groups from JSON files.

Author: Alex Waddell (AWS)
Date : 4th February 2026
"""

import boto3
import json
import argparse
import sys
import os
from botocore.exceptions import ClientError
from typing import Optional, Tuple, Dict, List


def get_waf_client(scope: str, region: str = 'us-east-1'):
    """
    Create WAFv2 client.
    
    Args:
        scope: 'REGIONAL' or 'CLOUDFRONT'
        region: AWS region (use 'us-east-1' for CLOUDFRONT scope)
    """
    if scope == 'CLOUDFRONT':
        return boto3.client('wafv2', region_name='us-east-1')
    return boto3.client('wafv2', region_name=region)


def list_rule_groups(waf_client, scope: str) -> List[Dict]:
    """List all rule groups for the given scope."""
    rule_groups = []
    next_marker = None
    
    while True:
        params = {'Scope': scope}
        if next_marker:
            params['NextMarker'] = next_marker
            
        response = waf_client.list_rule_groups(**params)
        rule_groups.extend(response.get('RuleGroups', []))
        
        next_marker = response.get('NextMarker')
        if not next_marker:
            break
    
    return rule_groups


def get_rule_group(waf_client, name: str, scope: str, rule_group_id: str) -> Dict:
    """Get a specific rule group by name and ID."""
    try:
        response = waf_client.get_rule_group(
            Name=name,
            Scope=scope,
            Id=rule_group_id
        )
        return response
    except ClientError as e:
        print(f"Error getting rule group: {e}")
        raise


def get_rule_group_by_arn(waf_client, arn: str) -> Dict:
    """Get a specific rule group by ARN."""
    try:
        response = waf_client.get_rule_group(ARN=arn)
        return response
    except ClientError as e:
        print(f"Error getting rule group: {e}")
        raise


def export_rules_for_json_editor(rule_group_response: dict) -> dict:
    """
    Format rules for the WAF JSON editor.
    """
    rule_group = rule_group_response.get('RuleGroup', {})
    rules = rule_group.get('Rules', [])
    
    return {
        "Rules": rules
    }


def export_full_rule_group(rule_group_response: dict) -> dict:
    """
    Export the full rule group configuration.
    """
    rule_group = rule_group_response.get('RuleGroup', {})
    # Don't export lock token as it's sensitive and time-limited
    
    export_data = {
        "RuleGroup": {
            "Name": rule_group.get('Name'),
            "Id": rule_group.get('Id'),
            "ARN": rule_group.get('ARN'),
            "Capacity": rule_group.get('Capacity'),
            "Rules": rule_group.get('Rules', []),
            "VisibilityConfig": rule_group.get('VisibilityConfig'),
            "Description": rule_group.get('Description', ''),
        }
    }
    
    # Add optional fields if they exist
    if rule_group.get('CustomResponseBodies'):
        export_data['RuleGroup']['CustomResponseBodies'] = rule_group['CustomResponseBodies']
    if rule_group.get('LabelNamespace'):
        export_data['RuleGroup']['LabelNamespace'] = rule_group['LabelNamespace']
    
    return export_data


def save_to_file(data: dict, filename: str, pretty: bool = True):
    """Save data to a JSON file."""
    # Validate path to prevent directory traversal
    abs_path = os.path.abspath(filename)
    if not abs_path.startswith(os.path.abspath(os.getcwd())):
        if '..' in filename or filename.startswith('/'):
            print(f"Error: Invalid file path '{filename}' - path traversal detected")
            sys.exit(1)
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            if pretty:
                json.dump(data, f, indent=2, default=str)
            else:
                json.dump(data, f, default=str)
        print(f"Successfully saved to {filename}")
    except (IOError, OSError, PermissionError) as e:
        print(f"Error: Failed to write to file '{filename}': {e}")
        sys.exit(1)


def load_from_file(filename: str) -> dict:
    """Load data from a JSON file."""
    # Validate path to prevent directory traversal
    abs_path = os.path.abspath(filename)
    if not abs_path.startswith(os.path.abspath(os.getcwd())):
        if '..' in filename or filename.startswith('/'):
            print(f"Error: Invalid file path '{filename}' - path traversal detected")
            sys.exit(1)
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in file '{filename}': {e}")
        sys.exit(1)


def interactive_select_rule_group(waf_client, scope: str) -> Tuple[Optional[str], Optional[str]]:
    """Interactively select a rule group from the list."""
    print(f"\nFetching rule groups for scope: {scope}...")
    rule_groups = list_rule_groups(waf_client, scope)
    
    if not rule_groups:
        print("No rule groups found.")
        return None, None
    
    print("\nAvailable Rule Groups:")
    print("-" * 80)
    for i, rg in enumerate(rule_groups, 1):
        print(f"{i}. {rg['Name']}")
        print(f"   ID: {rg['Id']}")
        print(f"   ARN: {rg['ARN']}")
        print()
    
    while True:
        try:
            choice = int(input("Select a rule group (enter number): "))
            if 1 <= choice <= len(rule_groups):
                selected = rule_groups[choice - 1]
                return selected['Name'], selected['Id']
            print("Invalid selection. Please try again.")
        except ValueError:
            print("Please enter a valid number.")


def check_capacity(waf_client, scope: str, rules: List[Dict]) -> int:
    """
    Check the capacity required for a set of rules.
    """
    try:
        response = waf_client.check_capacity(
            Scope=scope,
            Rules=rules
        )
        return response['Capacity']
    except ClientError as e:
        print(f"Warning: Could not calculate capacity: {e}")
        return 0


def create_rule_group(
    waf_client,
    name: str,
    scope: str,
    capacity: int,
    rules: List[Dict],
    description: str = '',
    visibility_config: Optional[Dict] = None,
    tags: Optional[List[Dict]] = None,
    custom_response_bodies: Optional[Dict] = None
) -> Dict:
    """
    Create a new WAF rule group.
    """
    # Default visibility config
    if visibility_config is None:
        visibility_config = {
            'SampledRequestsEnabled': True,
            'CloudWatchMetricsEnabled': True,
            'MetricName': name.replace('-', '').replace('_', '')[:128]
        }
    
    params = {
        'Name': name,
        'Scope': scope,
        'Capacity': capacity,
        'Rules': rules,
        'VisibilityConfig': visibility_config
    }
    
    if description:
        params['Description'] = description
    
    if tags:
        params['Tags'] = tags
    
    if custom_response_bodies:
        params['CustomResponseBodies'] = custom_response_bodies
    
    try:
        response = waf_client.create_rule_group(**params)
        return response
    except ClientError as e:
        print(f"Error creating rule group: {e}")
        raise


def update_rule_group(
    waf_client,
    name: str,
    scope: str,
    rule_group_id: str,
    rules: List[Dict],
    lock_token: str,
    description: str = '',
    visibility_config: Optional[Dict] = None,
    custom_response_bodies: Optional[Dict] = None
) -> Dict:
    """
    Update an existing WAF rule group.
    """
    if visibility_config is None:
        visibility_config = {
            'SampledRequestsEnabled': True,
            'CloudWatchMetricsEnabled': True,
            'MetricName': name.replace('-', '').replace('_', '')[:128]
        }
    
    params = {
        'Name': name,
        'Scope': scope,
        'Id': rule_group_id,
        'Rules': rules,
        'VisibilityConfig': visibility_config,
        'LockToken': lock_token
    }
    
    if description:
        params['Description'] = description
    
    if custom_response_bodies:
        params['CustomResponseBodies'] = custom_response_bodies
    
    try:
        response = waf_client.update_rule_group(**params)
        return response
    except ClientError as e:
        print(f"Error updating rule group: {e}")
        raise


def extract_rules_from_json(data: dict) -> Tuple[List[Dict], Optional[Dict], Optional[Dict], Optional[str]]:
    """
    Extract rules from various JSON formats.
    
    Returns:
        Tuple of (rules, visibility_config, custom_response_bodies, description)
    """
    if not isinstance(data, (dict, list)):
        print("Error: Invalid JSON format - expected dict or list")
        sys.exit(1)
    
    rules = []
    visibility_config = None
    custom_response_bodies = None
    description = None
    
    # Format 1: Just rules array {"Rules": [...]}
    if isinstance(data, dict) and 'Rules' in data and isinstance(data['Rules'], list):
        rules = data['Rules']
    
    # Format 2: Full export {"RuleGroup": {...}}
    elif isinstance(data, dict) and 'RuleGroup' in data:
        rule_group = data['RuleGroup']
        rules = rule_group.get('Rules', [])
        visibility_config = rule_group.get('VisibilityConfig')
        custom_response_bodies = rule_group.get('CustomResponseBodies')
        description = rule_group.get('Description')
    
    # Format 3: Direct rules array [...]
    elif isinstance(data, list):
        rules = data
    
    return rules, visibility_config, custom_response_bodies, description


def do_export(args):
    """Handle the export command."""
    # Set AWS profile if specified
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)
    
    # Handle ARN-based lookup
    if args.arn:
        waf_client = boto3.client('wafv2', region_name='us-east-1')
        if ':regional/' in args.arn:
            arn_parts = args.arn.split(':')
            region = arn_parts[3]
            waf_client = boto3.client('wafv2', region_name=region)
        
        print(f"Fetching rule group by ARN: {args.arn}")
        response = get_rule_group_by_arn(waf_client, args.arn)
        rule_group_name = response.get('RuleGroup', {}).get('Name')
        if not rule_group_name:
            print("Error: Could not retrieve rule group name from response")
            sys.exit(1)
    else:
        if not args.scope:
            print("Error: --scope is required when not using --arn")
            sys.exit(1)
        
        waf_client = get_waf_client(args.scope, args.region)
        
        # List only mode
        if args.list:
            rule_groups = list_rule_groups(waf_client, args.scope)
            print(f"\nRule Groups ({args.scope}):")
            print("-" * 80)
            for rg in rule_groups:
                print(f"Name: {rg['Name']}")
                print(f"ID: {rg['Id']}")
                print(f"ARN: {rg['ARN']}")
                print()
            return
        
        # Interactive or direct selection
        if args.name and args.id:
            rule_group_name = args.name
            rule_group_id = args.id
        else:
            rule_group_name, rule_group_id = interactive_select_rule_group(
                waf_client, args.scope
            )
            if not rule_group_name:
                return
        
        print(f"\nFetching rule group: {rule_group_name}")
        response = get_rule_group(
            waf_client, rule_group_name, args.scope, rule_group_id
        )
    
    # Determine output format
    if args.full:
        export_data = export_full_rule_group(response)
        default_suffix = "-full.json"
    else:
        export_data = export_rules_for_json_editor(response)
        default_suffix = "-rules.json"
    
    # Determine output filename
    if args.output:
        output_file = args.output
    else:
        safe_name = rule_group_name.replace(' ', '-').replace('/', '-')
        output_file = f"{safe_name}{default_suffix}"
    
    # Display summary
    rule_count = len(export_data.get('Rules', export_data.get('RuleGroup', {}).get('Rules', [])))
    print(f"\nRule Group: {rule_group_name}")
    print(f"Total Rules: {rule_count}")
    print(f"Capacity: {response['RuleGroup'].get('Capacity', 'N/A')}")
    
    # Save to file
    save_to_file(export_data, output_file)
    
    print(f"\n{'='*60}")
    print("To import into a new rule group:")
    print(f"  python {sys.argv[0]} create --scope {args.scope or 'REGIONAL'} \\")
    print(f"      --region {args.region} --name NewRuleGroupName \\")
    print(f"      --input {output_file}")
    print('='*60)


def do_create(args):
    """Handle the create command."""
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)
    
    if not args.scope:
        print("Error: --scope is required")
        sys.exit(1)
    
    if not args.name:
        print("Error: --name is required for the new rule group")
        sys.exit(1)
    
    if not args.input:
        print("Error: --input JSON file is required")
        sys.exit(1)
    
    # Load rules from file
    print(f"Loading rules from: {args.input}")
    data = load_from_file(args.input)
    
    rules, visibility_config, custom_response_bodies, description = extract_rules_from_json(data)
    
    if not rules:
        print("Error: No rules found in the input file")
        sys.exit(1)
    
    print(f"Found {len(rules)} rules")
    
    # Use provided description or from file
    if args.description:
        description = args.description
    
    waf_client = get_waf_client(args.scope, args.region)
    
    # Calculate or use provided capacity
    if args.capacity:
        capacity = args.capacity
        print(f"Using specified capacity: {capacity}")
    else:
        print("Calculating required capacity...")
        capacity = check_capacity(waf_client, args.scope, rules)
        if capacity == 0:
            print("Error: Could not calculate capacity. Please specify --capacity manually.")
            sys.exit(1)
        print(f"Calculated capacity: {capacity}")
        
        # Add some buffer if requested
        if args.capacity_buffer:
            original_capacity = capacity
            capacity = int(capacity * (1 + args.capacity_buffer / 100))
            print(f"Adding {args.capacity_buffer}% buffer: {original_capacity} -> {capacity}")
    
    # Parse tags if provided
    tags = None
    if args.tags:
        tags = []
        for tag in args.tags:
            if '=' in tag:
                key, value = tag.split('=', 1)
                tags.append({'Key': key, 'Value': value})
    
    # Confirm creation
    print(f"\n{'='*60}")
    print("Rule Group Configuration:")
    print(f"  Name: {args.name}")
    print(f"  Scope: {args.scope}")
    print(f"  Region: {args.region}")
    print(f"  Capacity: {capacity}")
    print(f"  Rules: {len(rules)}")
    print(f"  Description: {description or '(none)'}")
    if tags:
        print(f"  Tags: {tags}")
    print('='*60)
    
    if not args.yes:
        confirm = input("\nCreate this rule group? (yes/no): ")
        if confirm.lower() not in ['yes', 'y']:
            print("Aborted.")
            return
    
    # Create the rule group
    print("\nCreating rule group...")
    try:
        response = create_rule_group(
            waf_client=waf_client,
            name=args.name,
            scope=args.scope,
            capacity=capacity,
            rules=rules,
            description=description or '',
            visibility_config=visibility_config,
            tags=tags,
            custom_response_bodies=custom_response_bodies
        )
        
        summary = response['Summary']
        print(f"\n✓ Rule group created successfully!")
        print(f"  Name: {summary['Name']}")
        print(f"  ID: {summary['Id']}")
        print(f"  ARN: {summary['ARN']}")
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'WAFDuplicateItemException':
            print(f"\nError: A rule group with name '{args.name}' already exists.")
            print("Use a different name or delete the existing rule group first.")
        elif error_code == 'WAFLimitsExceededException':
            print(f"\nError: WAF limits exceeded. {error_message}")
        elif error_code == 'WAFInvalidParameterException':
            print(f"\nError: Invalid parameter. {error_message}")
        else:
            print(f"\nError: {error_code} - {error_message}")
        sys.exit(1)


def do_update(args):
    """Handle the update command."""
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)
    
    if not args.scope:
        print("Error: --scope is required")
        sys.exit(1)
    
    if not args.name or not args.id:
        print("Error: --name and --id are required for updating")
        sys.exit(1)
    
    if not args.input:
        print("Error: --input JSON file is required")
        sys.exit(1)
    
    # Load rules from file
    print(f"Loading rules from: {args.input}")
    data = load_from_file(args.input)
    
    rules, visibility_config, custom_response_bodies, description = extract_rules_from_json(data)
    
    if not rules:
        print("Error: No rules found in the input file")
        sys.exit(1)
    
    print(f"Found {len(rules)} rules")
    
    waf_client = get_waf_client(args.scope, args.region)
    
    # Get current rule group to obtain lock token
    print(f"Fetching current rule group: {args.name}")
    try:
        current = get_rule_group(waf_client, args.name, args.scope, args.id)
        lock_token = current['LockToken']
        current_capacity = current['RuleGroup']['Capacity']
        print(f"Current capacity: {current_capacity}")
    except ClientError as e:
        print(f"Error: Could not find rule group '{args.name}' with ID '{args.id}'")
        sys.exit(1)
    
    # Check new capacity requirements
    print("Checking capacity requirements...")
    required_capacity = check_capacity(waf_client, args.scope, rules)
    print(f"Required capacity for new rules: {required_capacity}")
    
    if required_capacity > current_capacity:
        print(f"\nWarning: New rules require capacity {required_capacity}, but rule group has {current_capacity}")
        print("You cannot increase capacity of an existing rule group.")
        print("Consider creating a new rule group with higher capacity instead.")
        sys.exit(1)
    
    # Use provided description or from file or keep existing
    if args.description:
        description = args.description
    elif not description:
        description = current['RuleGroup'].get('Description', '')
    
    # Use existing visibility config if not in file
    if not visibility_config:
        visibility_config = current['RuleGroup'].get('VisibilityConfig')
    
    # Confirm update
    print(f"\n{'='*60}")
    print("Update Configuration:")
    print(f"  Name: {args.name}")
    print(f"  ID: {args.id}")
    print(f"  Scope: {args.scope}")
    print(f"  Current Rules: {len(current['RuleGroup'].get('Rules', []))}")
    print(f"  New Rules: {len(rules)}")
    print(f"  Description: {description or '(none)'}")
    print('='*60)
    
    if not args.yes:
        confirm = input("\nUpdate this rule group? (yes/no): ")
        if confirm.lower() not in ['yes', 'y']:
            print("Aborted.")
            return
    
    # Update the rule group
    print("\nUpdating rule group...")
    try:
        response = update_rule_group(
            waf_client=waf_client,
            name=args.name,
            scope=args.scope,
            rule_group_id=args.id,
            rules=rules,
            lock_token=lock_token,
            description=description,
            visibility_config=visibility_config,
            custom_response_bodies=custom_response_bodies
        )
        
        print(f"\n✓ Rule group updated successfully!")
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'WAFOptimisticLockException':
            print(f"\nError: Rule group was modified by another process. Please try again.")
        else:
            print(f"\nError: {error_code} - {error_message}")
        sys.exit(1)


def do_clone(args):
    """Handle the clone command - export and create in one step."""
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)
    
    if not args.scope:
        print("Error: --scope is required")
        sys.exit(1)
    
    if not args.new_name:
        print("Error: --new-name is required")
        sys.exit(1)
    
    waf_client = get_waf_client(args.scope, args.region)
    dest_waf_client = waf_client
    
    # If destination region is different
    if args.dest_region and args.dest_region != args.region:
        dest_waf_client = get_waf_client(args.scope, args.dest_region)
    
    # Get source rule group
    if args.source_name and args.source_id:
        source_name = args.source_name
        source_id = args.source_id
    else:
        source_name, source_id = interactive_select_rule_group(waf_client, args.scope)
        if not source_name:
            return
    
    print(f"\nFetching source rule group: {source_name}")
    source = get_rule_group(waf_client, source_name, args.scope, source_id)
    source_rg = source['RuleGroup']
    
    rules = source_rg.get('Rules', [])
    print(f"Found {len(rules)} rules")
    
    # Calculate capacity for destination
    if args.capacity:
        capacity = args.capacity
    else:
        capacity = source_rg.get('Capacity', 100)
    
    # Confirm
    print(f"\n{'='*60}")
    print("Clone Configuration:")
    print(f"  Source: {source_name} ({args.region})")
    print(f"  Destination: {args.new_name} ({args.dest_region or args.region})")
    print(f"  Capacity: {capacity}")
    print(f"  Rules: {len(rules)}")
    print('='*60)
    
    if not args.yes:
        confirm = input("\nCreate cloned rule group? (yes/no): ")
        if confirm.lower() not in ['yes', 'y']:
            print("Aborted.")
            return
    
    # Create the new rule group
    print("\nCreating cloned rule group...")
    try:
        response = create_rule_group(
            waf_client=dest_waf_client,
            name=args.new_name,
            scope=args.scope,
            capacity=capacity,
            rules=rules,
            description=args.description or source_rg.get('Description', f'Cloned from {source_name}'),
            visibility_config=source_rg.get('VisibilityConfig'),
            custom_response_bodies=source_rg.get('CustomResponseBodies')
        )
        
        summary = response['Summary']
        print(f"\n✓ Rule group cloned successfully!")
        print(f"  Name: {summary['Name']}")
        print(f"  ID: {summary['Id']}")
        print(f"  ARN: {summary['ARN']}")
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        print(f"\nError: {error_code} - {error_message}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description='AWS WAF Rule Group Export, Import, and Management Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Common Usage:
  # Show help for a specific command
  python waf_manager.py export --help
  python waf_manager.py create --help
  
  # Quick export
  python waf_manager.py export --scope REGIONAL --region us-east-1
  
  # Quick create
  python waf_manager.py create --scope REGIONAL --region us-east-1 --name MyRules --input rules.json

For detailed examples, use --help with any command (export, create, update, clone, list)
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands: export, create, update, clone, list')
    
    # ========== EXPORT COMMAND ==========
    export_parser = subparsers.add_parser(
        'export',
        help='Export rules from a WAF rule group to JSON',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode - select from list
  python waf_manager.py export --scope REGIONAL --region us-east-1

  # Export by name and ID
  python waf_manager.py export --scope REGIONAL --region us-east-1 --name MyRuleGroup --id abc123

  # Export by ARN (auto-detects region)
  python waf_manager.py export --arn arn:aws:wafv2:us-east-1:123456789:regional/rulegroup/MyRuleGroup/abc123

  # Export full configuration (includes metadata)
  python waf_manager.py export --scope REGIONAL --region us-east-1 --name MyRuleGroup --id abc123 --full

  # List all rule groups
  python waf_manager.py export --scope REGIONAL --region us-east-1 --list
        """
    )
    export_parser.add_argument('--scope', choices=['REGIONAL', 'CLOUDFRONT'], 
                               help='WAF scope: REGIONAL for ALB/API Gateway, CLOUDFRONT for CloudFront distributions')
    export_parser.add_argument('--region', default='us-east-1', 
                               help='AWS region (default: us-east-1, always us-east-1 for CLOUDFRONT scope)')
    export_parser.add_argument('--name', help='Rule group name (use with --id, or omit for interactive selection)')
    export_parser.add_argument('--id', help='Rule group ID (use with --name, or omit for interactive selection)')
    export_parser.add_argument('--arn', help='Rule group ARN (alternative to --name/--id, auto-detects region)')
    export_parser.add_argument('--output', '-o', help='Output JSON filename (default: auto-generated from rule group name)')
    export_parser.add_argument('--full', action='store_true', 
                               help='Export full configuration including metadata, lock token, and optional fields')
    export_parser.add_argument('--list', action='store_true', 
                               help='List all rule groups in the scope and exit (no export)')
    export_parser.add_argument('--profile', help='AWS profile name from ~/.aws/credentials')
    
    # ========== CREATE COMMAND ==========
    create_parser = subparsers.add_parser(
        'create',
        help='Create a new WAF rule group from JSON',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create from exported JSON (auto-calculate capacity)
  python waf_manager.py create --scope REGIONAL --region us-east-1 \\
      --name NewRuleGroup --input exported-rules.json

  # Create with specific capacity
  python waf_manager.py create --scope REGIONAL --region us-east-1 \\
      --name NewRuleGroup --input rules.json --capacity 500

  # Create with capacity buffer (adds 20% safety margin)
  python waf_manager.py create --scope REGIONAL --region us-east-1 \\
      --name NewRuleGroup --input rules.json --capacity-buffer 20

  # Create with tags and description
  python waf_manager.py create --scope REGIONAL --region us-east-1 \\
      --name NewRuleGroup --input rules.json \\
      --description "Production WAF rules" \\
      --tags Environment=prod Team=security Owner=john.doe

  # Create without confirmation prompt (for automation)
  python waf_manager.py create --scope REGIONAL --region us-east-1 \\
      --name NewRuleGroup --input rules.json --yes
        """
    )
    create_parser.add_argument('--scope', choices=['REGIONAL', 'CLOUDFRONT'], required=True,
                               help='WAF scope: REGIONAL for ALB/API Gateway, CLOUDFRONT for CloudFront distributions')
    create_parser.add_argument('--region', default='us-east-1',
                               help='AWS region (default: us-east-1, always us-east-1 for CLOUDFRONT scope)')
    create_parser.add_argument('--name', required=True, 
                               help='Name for the new rule group (must be unique within scope)')
    create_parser.add_argument('--input', '-i', required=True, 
                               help='Input JSON file containing rules (supports multiple formats)')
    create_parser.add_argument('--capacity', type=int, 
                               help='Rule group capacity in WCUs (auto-calculated if not specified, max: 1500)')
    create_parser.add_argument('--capacity-buffer', type=int, default=0, 
                               help='Percentage buffer to add to calculated capacity (e.g., 20 for 20%% extra)')
    create_parser.add_argument('--description', 
                               help='Description for the rule group (optional, max 256 characters)')
    create_parser.add_argument('--tags', nargs='+', 
                               help='Tags in Key=Value format (space-separated, e.g., Env=prod Team=security)')
    create_parser.add_argument('--yes', '-y', action='store_true', 
                               help='Skip confirmation prompt (useful for automation/CI-CD)')
    create_parser.add_argument('--profile', help='AWS profile name from ~/.aws/credentials')
    
    # ========== UPDATE COMMAND ==========
    update_parser = subparsers.add_parser(
        'update',
        help='Update an existing WAF rule group from JSON',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Update existing rule group with new rules
  python waf_manager.py update --scope REGIONAL --region us-east-1 \\
      --name MyRuleGroup --id abc123 --input new-rules.json

  # Update with new description
  python waf_manager.py update --scope REGIONAL --region us-east-1 \\
      --name MyRuleGroup --id abc123 --input rules.json \\
      --description "Updated rules for Q1 2026"

  # Update without confirmation (automation)
  python waf_manager.py update --scope REGIONAL --region us-east-1 \\
      --name MyRuleGroup --id abc123 --input rules.json --yes

Note: You cannot increase capacity of an existing rule group. If new rules require
more capacity, you must create a new rule group with higher capacity.
        """
    )
    update_parser.add_argument('--scope', choices=['REGIONAL', 'CLOUDFRONT'], required=True,
                               help='WAF scope: REGIONAL for ALB/API Gateway, CLOUDFRONT for CloudFront distributions')
    update_parser.add_argument('--region', default='us-east-1',
                               help='AWS region (default: us-east-1, always us-east-1 for CLOUDFRONT scope)')
    update_parser.add_argument('--name', required=True, 
                               help='Name of the rule group to update')
    update_parser.add_argument('--id', required=True, 
                               help='ID of the rule group to update (required for lock token)')
    update_parser.add_argument('--input', '-i', required=True, 
                               help='Input JSON file containing new rules')
    update_parser.add_argument('--description', 
                               help='New description for the rule group (optional)')
    update_parser.add_argument('--yes', '-y', action='store_true', 
                               help='Skip confirmation prompt (useful for automation/CI-CD)')
    update_parser.add_argument('--profile', help='AWS profile name from ~/.aws/credentials')
    
    # ========== CLONE COMMAND ==========
    clone_parser = subparsers.add_parser(
        'clone',
        help='Clone a WAF rule group (export and create in one step)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Clone to same region with new name
  python waf_manager.py clone --scope REGIONAL --region us-east-1 \\
      --source-name OldRuleGroup --source-id abc123 --new-name NewRuleGroup

  # Clone to different region (disaster recovery)
  python waf_manager.py clone --scope REGIONAL --region us-east-1 \\
      --source-name MyRuleGroup --source-id abc123 \\
      --new-name MyRuleGroup-DR --dest-region us-east-1

  # Interactive source selection
  python waf_manager.py clone --scope REGIONAL --region us-east-1 --new-name ClonedGroup

  # Clone with custom capacity and description
  python waf_manager.py clone --scope REGIONAL --region us-east-1 \\
      --source-name ProdRules --source-id abc123 \\
      --new-name DevRules --capacity 1000 \\
      --description "Development environment rules"
        """
    )
    clone_parser.add_argument('--scope', choices=['REGIONAL', 'CLOUDFRONT'], required=True,
                              help='WAF scope: REGIONAL for ALB/API Gateway, CLOUDFRONT for CloudFront distributions')
    clone_parser.add_argument('--region', default='us-east-1', 
                              help='Source region (default: us-east-1)')
    clone_parser.add_argument('--source-name', 
                              help='Source rule group name (omit for interactive selection)')
    clone_parser.add_argument('--source-id', 
                              help='Source rule group ID (omit for interactive selection)')
    clone_parser.add_argument('--new-name', required=True, 
                              help='Name for the cloned rule group (must be unique)')
    clone_parser.add_argument('--dest-region', 
                              help='Destination region (default: same as source region)')
    clone_parser.add_argument('--capacity', type=int, 
                              help='Override capacity for cloned rule group (default: same as source)')
    clone_parser.add_argument('--description', 
                              help='Description for cloned rule group (default: "Cloned from <source>")')
    clone_parser.add_argument('--yes', '-y', action='store_true', 
                              help='Skip confirmation prompt (useful for automation/CI-CD)')
    clone_parser.add_argument('--profile', help='AWS profile name from ~/.aws/credentials')
    
    # ========== LIST COMMAND ==========
    list_parser = subparsers.add_parser(
        'list',
        help='List all WAF rule groups',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all REGIONAL rule groups in us-east-1
  python waf_manager.py list --scope REGIONAL --region us-east-1

  # List all CLOUDFRONT rule groups
  python waf_manager.py list --scope CLOUDFRONT

  # List using specific AWS profile
  python waf_manager.py list --scope REGIONAL --region us-east-1 --profile production

Output includes: Name, ID, and ARN for each rule group
        """
    )
    list_parser.add_argument('--scope', choices=['REGIONAL', 'CLOUDFRONT'], required=True,
                            help='WAF scope: REGIONAL for ALB/API Gateway, CLOUDFRONT for CloudFront distributions')
    list_parser.add_argument('--region', default='us-east-1',
                            help='AWS region (default: us-east-1, always us-east-1 for CLOUDFRONT scope)')
    list_parser.add_argument('--profile', help='AWS profile name from ~/.aws/credentials')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'export':
        do_export(args)
    elif args.command == 'create':
        do_create(args)
    elif args.command == 'update':
        do_update(args)
    elif args.command == 'clone':
        do_clone(args)
    elif args.command == 'list':
        if args.profile:
            boto3.setup_default_session(profile_name=args.profile)
        waf_client = get_waf_client(args.scope, args.region)
        rule_groups = list_rule_groups(waf_client, args.scope)
        print(f"\nRule Groups ({args.scope} - {args.region}):")
        print("-" * 80)
        for rg in rule_groups:
            print(f"Name: {rg['Name']}")
            print(f"ID: {rg['Id']}")
            print(f"ARN: {rg['ARN']}")
            print()
        if not rule_groups:
            print("No rule groups found.")


if __name__ == '__main__':
    main()