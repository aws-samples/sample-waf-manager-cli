# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this
# software and associated documentation files (the "Software"), to deal in the Software
# without restriction, including without limitation the rights to use, copy, modify,
# merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# #!/usr/bin/env python3

import boto3
import json
import argparse
import sys
from botocore.exceptions import ClientError
from typing import Optional, Tuple, Dict, List


# ============================================================
# Client & Utility Functions
# ============================================================

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


def save_to_file(data: dict, filename: str, pretty: bool = True):
    """Save data to a JSON file."""
    with open(filename, 'w', encoding='utf-8') as f:
        if pretty:
            json.dump(data, f, indent=2, default=str)
        else:
            json.dump(data, f, default=str)
    print(f"Successfully saved to {filename}")


def load_from_file(filename: str) -> dict:
    """Load data from a JSON file."""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        print(f"Please check the file path and try again.")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in file '{filename}'")
        print(f"JSON Error: {e}")
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied reading file '{filename}'")
        sys.exit(1)
    except Exception as e:
        print(f"Error: Failed to read file '{filename}': {e}")
        sys.exit(1)


def confirm_action(message: str, skip: bool = False) -> bool:
    """Prompt for confirmation."""
    if skip:
        return True
    confirm = input(f"\n{message} (yes/no): ")
    return confirm.lower() in ['yes', 'y']


def validate_scope_required(args, command_name: str):
    """Validate that scope is provided when required."""
    if not hasattr(args, 'scope') or not args.scope:
        print(f"Error: --scope is required for '{command_name}' command")
        print("Choose: --scope REGIONAL or --scope CLOUDFRONT")
        sys.exit(1)


def validate_required_params(args, command_name: str, required_params: List[str]):
    """Validate that all required parameters are provided."""
    missing = []
    for param in required_params:
        if not hasattr(args, param) or getattr(args, param) is None:
            missing.append(f"--{param.replace('_', '-')}")
    
    if missing:
        print(f"Error: Missing required parameter(s) for '{command_name}' command:")
        for param in missing:
            print(f"  {param}")
        sys.exit(1)


def validate_file_exists(filepath: str, param_name: str):
    """Validate that a file exists and is readable."""
    import os
    
    if not filepath:
        print(f"Error: No file path provided for {param_name}")
        sys.exit(1)
    
    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        print(f"Parameter: {param_name}")
        sys.exit(1)
    
    if not os.path.isfile(filepath):
        print(f"Error: Path is not a file: {filepath}")
        print(f"Parameter: {param_name}")
        sys.exit(1)
    
    if not os.access(filepath, os.R_OK):
        print(f"Error: File is not readable: {filepath}")
        print(f"Parameter: {param_name}")
        sys.exit(1)


def validate_mutually_exclusive(args, command_name: str, param_groups: List[List[str]], require_one: bool = True):
    """
    Validate mutually exclusive parameter groups.
    
    Args:
        args: Parsed arguments
        command_name: Name of the command
        param_groups: List of parameter groups (each group is a list of param names)
        require_one: If True, at least one group must be provided
    """
    provided_groups = []
    
    for group in param_groups:
        if all(hasattr(args, p) and getattr(args, p) is not None for p in group):
            provided_groups.append(group)
    
    if len(provided_groups) > 1:
        print(f"Error: Mutually exclusive parameters provided for '{command_name}' command:")
        for group in provided_groups:
            params = ', '.join([f"--{p.replace('_', '-')}" for p in group])
            print(f"  Group: {params}")
        sys.exit(1)
    
    if require_one and len(provided_groups) == 0:
        print(f"Error: One of the following parameter groups is required for '{command_name}' command:")
        for group in param_groups:
            params = ', '.join([f"--{p.replace('_', '-')}" for p in group])
            print(f"  {params}")
        sys.exit(1)


# ============================================================
# Rule Group Functions
# ============================================================

def list_rule_groups(waf_client, scope: str) -> List[Dict]:
    """List all rule groups for the given scope."""
    rule_groups = []
    next_marker = None
    
    try:
        while True:
            params = {'Scope': scope}
            if next_marker:
                params['NextMarker'] = next_marker

            try:
                response = waf_client.list_rule_groups(**params)
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                error_msg = e.response.get('Error', {}).get('Message', str(e))
                
                # Handle specific error cases
                if error_code == 'WAFInvalidParameterException':
                    print(f"Error: Invalid parameter for scope '{scope}'")
                    print(f"Details: {error_msg}")
                    raise
                elif error_code == 'WAFInternalErrorException':
                    print(f"Error: AWS WAF internal error occurred")
                    print(f"Details: {error_msg}")
                    print("Please try again in a few moments.")
                    raise
                elif error_code in ['AccessDeniedException', 'WAFAccessDeniedException']:
                    print(f"Error: Access denied when listing rule groups")
                    print(f"Details: {error_msg}")
                    print("Please check your IAM permissions for wafv2:ListRuleGroups")
                    raise
                elif error_code == 'ThrottlingException':
                    print(f"Error: Request throttled by AWS WAF")
                    print(f"Details: {error_msg}")
                    print("Please wait a moment and try again.")
                    raise
                else:
                    print(f"Error listing rule groups: [{error_code}] {error_msg}")
                    raise
            
            # Safely extract rule groups from response
            current_groups = response.get('RuleGroups', [])
            if not isinstance(current_groups, list):
                print(f"Warning: Unexpected response format - RuleGroups is not a list")
                current_groups = []
            
            rule_groups.extend(current_groups)

            next_marker = response.get('NextMarker')
            if not next_marker:
                break
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        print(f"Retrieved {len(rule_groups)} rule groups before cancellation.")
        raise
    except Exception as e:
        if not isinstance(e, ClientError):
            print(f"Unexpected error while listing rule groups: {e}")
        raise

    return rule_groups


def get_rule_group(waf_client, name: str, scope: str, rule_group_id: str) -> Dict:
    """Get a specific rule group by name and ID."""
    try:
        response = waf_client.get_rule_group(
            Name=name,
            Scope=scope,
            Id=rule_group_id
        )
        
        # Validate response structure
        if 'RuleGroup' not in response:
            print(f"Warning: Unexpected response format - missing 'RuleGroup' key")
            print(f"Response keys: {list(response.keys())}")
        
        return response
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        
        # Handle specific error cases
        if error_code == 'WAFNonexistentItemException':
            print(f"Error: Rule group not found")
            print(f"  Name: {name}")
            print(f"  ID: {rule_group_id}")
            print(f"  Scope: {scope}")
            print(f"Details: {error_msg}")
            print("\nPossible causes:")
            print("  - Rule group was deleted")
            print("  - Incorrect name or ID")
            print("  - Wrong scope (REGIONAL vs CLOUDFRONT)")
            print("  - Rule group exists in a different region")
            raise
        elif error_code == 'WAFInvalidParameterException':
            print(f"Error: Invalid parameter")
            print(f"  Name: {name}")
            print(f"  ID: {rule_group_id}")
            print(f"  Scope: {scope}")
            print(f"Details: {error_msg}")
            print("\nCheck that:")
            print("  - Name and ID match exactly")
            print("  - Scope is correct (REGIONAL or CLOUDFRONT)")
            print("  - ID format is valid")
            raise
        elif error_code in ['AccessDeniedException', 'WAFAccessDeniedException']:
            print(f"Error: Access denied when getting rule group '{name}'")
            print(f"Details: {error_msg}")
            print("Please check your IAM permissions for wafv2:GetRuleGroup")
            raise
        elif error_code == 'WAFInternalErrorException':
            print(f"Error: AWS WAF internal error occurred")
            print(f"Details: {error_msg}")
            print("Please try again in a few moments.")
            raise
        elif error_code == 'ThrottlingException':
            print(f"Error: Request throttled by AWS WAF")
            print(f"Details: {error_msg}")
            print("Please wait a moment and try again.")
            raise
        elif error_code == 'WAFInvalidResourceException':
            print(f"Error: Invalid resource")
            print(f"  Name: {name}")
            print(f"  ID: {rule_group_id}")
            print(f"Details: {error_msg}")
            print("The rule group may be in an invalid state or corrupted.")
            raise
        else:
            print(f"Error getting rule group '{name}': [{error_code}] {error_msg}")
            raise
    
    except Exception as e:
        if not isinstance(e, ClientError):
            print(f"Unexpected error getting rule group '{name}': {e}")
        raise


def get_rule_group_by_arn(waf_client, arn: str) -> Dict:
    """Get a specific rule group by ARN."""
    # Validate ARN format before making API call
    if not arn or not isinstance(arn, str):
        print(f"Error: Invalid ARN - must be a non-empty string")
        print(f"Provided: {arn}")
        raise ValueError("Invalid ARN format")
    
    if not arn.startswith('arn:'):
        print(f"Error: Invalid ARN format - must start with 'arn:'")
        print(f"Provided: {arn}")
        raise ValueError("Invalid ARN format")
    
    # Parse ARN to extract useful info for error messages
    arn_parts = arn.split(':')
    arn_resource = arn.split('/')[-2:] if '/' in arn else ['unknown', 'unknown']
    rule_group_name = arn_resource[0] if len(arn_resource) > 0 else 'unknown'
    
    try:
        response = waf_client.get_rule_group(ARN=arn)
        
        # Validate response structure
        if 'RuleGroup' not in response:
            print(f"Warning: Unexpected response format - missing 'RuleGroup' key")
            print(f"Response keys: {list(response.keys())}")
        
        return response
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        
        # Handle specific error cases
        if error_code == 'WAFNonexistentItemException':
            print(f"Error: Rule group not found")
            print(f"  ARN: {arn}")
            if rule_group_name != 'unknown':
                print(f"  Name (from ARN): {rule_group_name}")
            print(f"Details: {error_msg}")
            print("\nPossible causes:")
            print("  - Rule group was deleted")
            print("  - ARN is incorrect or malformed")
            print("  - Rule group exists in a different account")
            print("  - Wrong region in ARN")
            raise
        elif error_code == 'WAFInvalidParameterException':
            print(f"Error: Invalid ARN format")
            print(f"  ARN: {arn}")
            print(f"Details: {error_msg}")
            print("\nExpected ARN format:")
            print("  arn:aws:wafv2:region:account-id:scope/rulegroup/name/id")
            print("  Example: arn:aws:wafv2:us-east-1:123456789012:regional/rulegroup/MyRuleGroup/a1b2c3d4-...")
            raise
        elif error_code in ['AccessDeniedException', 'WAFAccessDeniedException']:
            print(f"Error: Access denied when getting rule group")
            print(f"  ARN: {arn}")
            print(f"Details: {error_msg}")
            print("Please check your IAM permissions for wafv2:GetRuleGroup")
            if len(arn_parts) >= 5:
                account_id = arn_parts[4]
                print(f"Note: Ensure you have access to account {account_id}")
            raise
        elif error_code == 'WAFInternalErrorException':
            print(f"Error: AWS WAF internal error occurred")
            print(f"Details: {error_msg}")
            print("Please try again in a few moments.")
            raise
        elif error_code == 'ThrottlingException':
            print(f"Error: Request throttled by AWS WAF")
            print(f"Details: {error_msg}")
            print("Please wait a moment and try again.")
            raise
        elif error_code == 'WAFInvalidResourceException':
            print(f"Error: Invalid resource")
            print(f"  ARN: {arn}")
            print(f"Details: {error_msg}")
            print("The rule group may be in an invalid state or the ARN is malformed.")
            raise
        elif error_code == 'ValidationException':
            print(f"Error: Validation failed")
            print(f"  ARN: {arn}")
            print(f"Details: {error_msg}")
            print("The ARN format is invalid or contains invalid characters.")
            raise
        else:
            print(f"Error getting rule group by ARN: [{error_code}] {error_msg}")
            print(f"  ARN: {arn}")
            raise
    
    except ValueError as e:
        # Re-raise validation errors from our checks
        raise
    except Exception as e:
        if not isinstance(e, (ClientError, ValueError)):
            print(f"Unexpected error getting rule group by ARN: {e}")
            print(f"  ARN: {arn}")
        raise


def interactive_select_rule_group(waf_client, scope: str) -> Tuple[Optional[str], Optional[str]]:
    """Interactively select a rule group from the list."""
    print(f"\nFetching rule groups for scope: {scope}...")
    
    try:
        rule_groups = list_rule_groups(waf_client, scope)
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        print(f"\nError: Failed to fetch rule groups")
        print(f"Error Code: {error_code}")
        print(f"Details: {error_msg}")
        return None, None
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        return None, None
    except Exception as e:
        print(f"\nUnexpected error while fetching rule groups: {e}")
        return None, None
    
    if not rule_groups:
        print("No rule groups found.")
        print(f"Scope: {scope}")
        print("\nPossible reasons:")
        print("  - No rule groups exist in this scope")
        print("  - Rule groups exist in a different region")
        print("  - Insufficient permissions to list rule groups")
        return None, None
    
    # Validate rule group data structure
    valid_rule_groups = []
    for i, rg in enumerate(rule_groups):
        if not isinstance(rg, dict):
            print(f"Warning: Skipping invalid rule group at index {i} (not a dict)")
            continue
        if 'Name' not in rg or 'Id' not in rg:
            print(f"Warning: Skipping rule group at index {i} (missing Name or Id)")
            continue
        valid_rule_groups.append(rg)
    
    if not valid_rule_groups:
        print("\nError: No valid rule groups found in response")
        print("All rule groups are missing required fields (Name, Id)")
        return None, None
    
    print(f"\nAvailable Rule Groups ({len(valid_rule_groups)}):")
    print("-" * 80)
    for i, rg in enumerate(valid_rule_groups, 1):
        print(f"{i}. {rg.get('Name', 'N/A')}")
        print(f"   ID: {rg.get('Id', 'N/A')}")
        if 'ARN' in rg:
            print(f"   ARN: {rg['ARN']}")
        if 'Description' in rg and rg['Description']:
            desc = rg['Description'][:60] + '...' if len(rg['Description']) > 60 else rg['Description']
            print(f"   Description: {desc}")
        print()

    max_attempts = 5
    attempts = 0
    
    while attempts < max_attempts:
        try:
            user_input = input(f"Select a rule group (1-{len(valid_rule_groups)}) or 'q' to quit: ").strip()
            
            if user_input.lower() in ['q', 'quit', 'exit']:
                print("Selection cancelled.")
                return None, None
            
            choice = int(user_input)
            
            if 1 <= choice <= len(valid_rule_groups):
                selected = valid_rule_groups[choice - 1]
                print(f"\nSelected: {selected['Name']}")
                return selected['Name'], selected['Id']
            else:
                attempts += 1
                print(f"Invalid selection. Please enter a number between 1 and {len(valid_rule_groups)}.")
                if attempts < max_attempts:
                    print(f"Attempts remaining: {max_attempts - attempts}")
                    
        except ValueError:
            attempts += 1
            print("Invalid input. Please enter a valid number.")
            if attempts < max_attempts:
                print(f"Attempts remaining: {max_attempts - attempts}")
        except KeyboardInterrupt:
            print("\n\nSelection cancelled by user.")
            return None, None
        except EOFError:
            print("\n\nEnd of input detected.")
            return None, None
    
    print(f"\nMaximum attempts ({max_attempts}) reached. Selection cancelled.")
    return None, None


def check_capacity(waf_client, scope: str, rules: List[Dict]) -> int:
    """
    Check the capacity required for a set of rules.
    Returns 0 if capacity cannot be calculated.
    """
    # Validate inputs
    if not rules:
        print("Warning: No rules provided for capacity check")
        return 0
    
    if not isinstance(rules, list):
        print(f"Warning: Rules must be a list, got {type(rules).__name__}")
        return 0
    
    # Validate rules structure
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            print(f"Warning: Rule at index {i} is not a dict, skipping capacity check")
            return 0
        if 'Name' not in rule:
            print(f"Warning: Rule at index {i} missing 'Name' field, skipping capacity check")
            return 0
    
    try:
        response = waf_client.check_capacity(
            Scope=scope,
            Rules=rules
        )
        
        # Validate response
        if 'Capacity' not in response:
            print("Warning: Capacity check response missing 'Capacity' field")
            print(f"Response keys: {list(response.keys())}")
            return 0
        
        capacity = response['Capacity']
        
        # Validate capacity value
        if not isinstance(capacity, (int, float)):
            print(f"Warning: Capacity value is not numeric: {type(capacity).__name__}")
            return 0
        
        if capacity < 0:
            print(f"Warning: Capacity value is negative: {capacity}")
            return 0
        
        return int(capacity)
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        
        # Handle specific error cases
        if error_code == 'WAFInvalidParameterException':
            print(f"Warning: Invalid parameter for capacity check")
            print(f"  Scope: {scope}")
            print(f"  Number of rules: {len(rules)}")
            print(f"Details: {error_msg}")
            print("\nPossible causes:")
            print("  - Invalid rule structure")
            print("  - Unsupported rule type")
            print("  - Invalid scope value")
            return 0
        elif error_code == 'WAFLimitsExceededException':
            print(f"Warning: Rules exceed WAF limits")
            print(f"  Number of rules: {len(rules)}")
            print(f"Details: {error_msg}")
            print("\nThe rule set is too large to calculate capacity.")
            print("Consider splitting into multiple rule groups.")
            return 0
        elif error_code in ['AccessDeniedException', 'WAFAccessDeniedException']:
            print(f"Warning: Access denied for capacity check")
            print(f"Details: {error_msg}")
            print("Please check your IAM permissions for wafv2:CheckCapacity")
            return 0
        elif error_code == 'WAFInternalErrorException':
            print(f"Warning: AWS WAF internal error during capacity check")
            print(f"Details: {error_msg}")
            print("Please try again in a few moments.")
            return 0
        elif error_code == 'ThrottlingException':
            print(f"Warning: Capacity check request throttled")
            print(f"Details: {error_msg}")
            print("Please wait a moment and try again.")
            return 0
        elif error_code == 'WAFInvalidResourceException':
            print(f"Warning: Invalid resource in rules")
            print(f"Details: {error_msg}")
            print("One or more rules reference invalid resources (IP sets, regex patterns, etc.)")
            return 0
        elif error_code == 'WAFUnavailableEntityException':
            print(f"Warning: Referenced entity unavailable")
            print(f"Details: {error_msg}")
            print("One or more rules reference entities that are temporarily unavailable.")
            return 0
        else:
            print(f"Warning: Could not calculate capacity")
            print(f"Error: [{error_code}] {error_msg}")
            return 0
    
    except KeyboardInterrupt:
        print("\n\nCapacity check cancelled by user.")
        return 0
    
    except Exception as e:
        print(f"Warning: Unexpected error during capacity check: {e}")
        return 0


# ============================================================
# Web ACL Functions
# ============================================================

def list_web_acls(waf_client, scope: str) -> List[Dict]:
    """List all Web ACLs."""
    web_acls = []
    next_marker = None

    try:
        while True:
            params = {'Scope': scope}
            if next_marker:
                params['NextMarker'] = next_marker

            try:
                response = waf_client.list_web_acls(**params)
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                error_msg = e.response.get('Error', {}).get('Message', str(e))
                
                # Handle specific error cases
                if error_code == 'WAFInvalidParameterException':
                    print(f"Error: Invalid parameter for scope '{scope}'")
                    print(f"Details: {error_msg}")
                    raise
                elif error_code == 'WAFInternalErrorException':
                    print(f"Error: AWS WAF internal error occurred")
                    print(f"Details: {error_msg}")
                    print("Please try again in a few moments.")
                    raise
                elif error_code in ['AccessDeniedException', 'WAFAccessDeniedException']:
                    print(f"Error: Access denied when listing Web ACLs")
                    print(f"Details: {error_msg}")
                    print("Please check your IAM permissions for wafv2:ListWebACLs")
                    raise
                elif error_code == 'ThrottlingException':
                    print(f"Error: Request throttled by AWS WAF")
                    print(f"Details: {error_msg}")
                    print("Please wait a moment and try again.")
                    raise
                elif error_code == 'WAFInvalidOperationException':
                    print(f"Error: Invalid operation")
                    print(f"Details: {error_msg}")
                    print("This may occur if the scope is not supported in this region.")
                    raise
                else:
                    print(f"Error listing Web ACLs: [{error_code}] {error_msg}")
                    raise
            
            # Safely extract Web ACLs from response
            current_acls = response.get('WebACLs', [])
            if not isinstance(current_acls, list):
                print(f"Warning: Unexpected response format - WebACLs is not a list")
                current_acls = []
            
            web_acls.extend(current_acls)

            next_marker = response.get('NextMarker')
            if not next_marker:
                break
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        print(f"Retrieved {len(web_acls)} Web ACLs before cancellation.")
        raise
    except Exception as e:
        if not isinstance(e, ClientError):
            print(f"Unexpected error while listing Web ACLs: {e}")
        raise

    return web_acls


def get_web_acl(waf_client, name: str, scope: str, web_acl_id: str) -> Dict:
    """Get a Web ACL by name and ID."""
    try:
        response = waf_client.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)
        
        # Validate response structure
        if 'WebACL' not in response:
            print(f"Warning: Unexpected response format - missing 'WebACL' key")
            print(f"Response keys: {list(response.keys())}")
        
        return response
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        
        # Handle specific error cases
        if error_code == 'WAFNonexistentItemException':
            print(f"Error: Web ACL not found")
            print(f"  Name: {name}")
            print(f"  ID: {web_acl_id}")
            print(f"  Scope: {scope}")
            print(f"Details: {error_msg}")
            print("\nPossible causes:")
            print("  - Web ACL was deleted")
            print("  - Incorrect name or ID")
            print("  - Wrong scope (REGIONAL vs CLOUDFRONT)")
            print("  - Web ACL exists in a different region")
            raise
        elif error_code == 'WAFInvalidParameterException':
            print(f"Error: Invalid parameter")
            print(f"  Name: {name}")
            print(f"  ID: {web_acl_id}")
            print(f"  Scope: {scope}")
            print(f"Details: {error_msg}")
            print("\nCheck that:")
            print("  - Name and ID match exactly")
            print("  - Scope is correct (REGIONAL or CLOUDFRONT)")
            print("  - ID format is valid")
            raise
        elif error_code in ['AccessDeniedException', 'WAFAccessDeniedException']:
            print(f"Error: Access denied when getting Web ACL '{name}'")
            print(f"Details: {error_msg}")
            print("Please check your IAM permissions for wafv2:GetWebACL")
            raise
        elif error_code == 'WAFInternalErrorException':
            print(f"Error: AWS WAF internal error occurred")
            print(f"Details: {error_msg}")
            print("Please try again in a few moments.")
            raise
        elif error_code == 'ThrottlingException':
            print(f"Error: Request throttled by AWS WAF")
            print(f"Details: {error_msg}")
            print("Please wait a moment and try again.")
            raise
        elif error_code == 'WAFInvalidResourceException':
            print(f"Error: Invalid resource")
            print(f"  Name: {name}")
            print(f"  ID: {web_acl_id}")
            print(f"Details: {error_msg}")
            print("The Web ACL may be in an invalid state or corrupted.")
            raise
        else:
            print(f"Error getting Web ACL '{name}': [{error_code}] {error_msg}")
            raise
    
    except Exception as e:
        if not isinstance(e, ClientError):
            print(f"Unexpected error getting Web ACL '{name}': {e}")
        raise


def get_web_acl_by_arn(waf_client, arn: str) -> Dict:
    """Get a Web ACL by ARN."""
    # Validate ARN format before parsing
    if not arn or not isinstance(arn, str):
        print(f"Error: Invalid ARN - must be a non-empty string")
        print(f"Provided: {arn}")
        raise ValueError("Invalid ARN format")
    
    if not arn.startswith('arn:'):
        print(f"Error: Invalid ARN format - must start with 'arn:'")
        print(f"Provided: {arn}")
        raise ValueError("Invalid ARN format")
    
    try:
        # ARN format: arn:aws:wafv2:region:account:scope/webacl/name/id
        parts = arn.split('/')
        if len(parts) < 4:
            print(f"Error: Invalid ARN format - insufficient components")
            print(f"  ARN: {arn}")
            print(f"  Expected format: arn:aws:wafv2:region:account:scope/webacl/name/id")
            raise ValueError(f"Invalid ARN format: {arn}")
        
        name = parts[-2]
        web_acl_id = parts[-1]
        
        arn_prefix = parts[0]
        arn_components = arn_prefix.split(':')
        if len(arn_components) < 6:
            print(f"Error: Invalid ARN format - insufficient prefix components")
            print(f"  ARN: {arn}")
            print(f"  Expected format: arn:aws:wafv2:region:account:scope/webacl/name/id")
            raise ValueError(f"Invalid ARN format: {arn}")
        
        scope_part = arn_components[-1]  # regional or global
        scope = 'CLOUDFRONT' if scope_part == 'global' else 'REGIONAL'
        region = arn_components[3] if arn_components[3] else 'us-east-1'

        client = get_waf_client(scope, region)
        response = client.get_web_acl(Name=name, Scope=scope, Id=web_acl_id)
        
        # Validate response structure
        if 'WebACL' not in response:
            print(f"Warning: Unexpected response format - missing 'WebACL' key")
            print(f"Response keys: {list(response.keys())}")
        
        return response
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        
        # Handle specific error cases
        if error_code == 'WAFNonexistentItemException':
            print(f"Error: Web ACL not found")
            print(f"  ARN: {arn}")
            if 'name' in locals():
                print(f"  Name (from ARN): {name}")
            print(f"Details: {error_msg}")
            print("\nPossible causes:")
            print("  - Web ACL was deleted")
            print("  - ARN is incorrect or malformed")
            print("  - Web ACL exists in a different account")
            print("  - Wrong region in ARN")
            raise
        elif error_code == 'WAFInvalidParameterException':
            print(f"Error: Invalid ARN or parameter")
            print(f"  ARN: {arn}")
            print(f"Details: {error_msg}")
            print("\nExpected ARN format:")
            print("  arn:aws:wafv2:region:account-id:scope/webacl/name/id")
            print("  Example: arn:aws:wafv2:us-east-1:123456789012:regional/webacl/MyWebACL/a1b2c3d4-...")
            raise
        elif error_code in ['AccessDeniedException', 'WAFAccessDeniedException']:
            print(f"Error: Access denied when getting Web ACL")
            print(f"  ARN: {arn}")
            print(f"Details: {error_msg}")
            print("Please check your IAM permissions for wafv2:GetWebACL")
            if len(arn.split(':')) >= 5:
                account_id = arn.split(':')[4]
                print(f"Note: Ensure you have access to account {account_id}")
            raise
        elif error_code == 'WAFInternalErrorException':
            print(f"Error: AWS WAF internal error occurred")
            print(f"Details: {error_msg}")
            print("Please try again in a few moments.")
            raise
        elif error_code == 'ThrottlingException':
            print(f"Error: Request throttled by AWS WAF")
            print(f"Details: {error_msg}")
            print("Please wait a moment and try again.")
            raise
        elif error_code == 'WAFInvalidResourceException':
            print(f"Error: Invalid resource")
            print(f"  ARN: {arn}")
            print(f"Details: {error_msg}")
            print("The Web ACL may be in an invalid state or the ARN is malformed.")
            raise
        elif error_code == 'ValidationException':
            print(f"Error: Validation failed")
            print(f"  ARN: {arn}")
            print(f"Details: {error_msg}")
            print("The ARN format is invalid or contains invalid characters.")
            raise
        else:
            print(f"Error getting Web ACL by ARN: [{error_code}] {error_msg}")
            print(f"  ARN: {arn}")
            raise
    
    except (IndexError, ValueError) as e:
        # Handle parsing errors
        if isinstance(e, ValueError) and "Invalid ARN format" in str(e):
            # Re-raise our validation errors
            raise
        print(f"Error parsing Web ACL ARN: {e}")
        print(f"  ARN: {arn}")
        print(f"\nExpected ARN format:")
        print("  arn:aws:wafv2:region:account-id:scope/webacl/name/id")
        raise ValueError(f"Failed to parse ARN: {arn}")
    
    except Exception as e:
        if not isinstance(e, (ClientError, ValueError, IndexError)):
            print(f"Unexpected error getting Web ACL by ARN: {e}")
            print(f"  ARN: {arn}")
        raise


def interactive_select_web_acl(waf_client, scope: str) -> Tuple[Optional[str], Optional[str]]:
    """Interactively select a Web ACL."""
    print(f"\nFetching Web ACLs for scope: {scope}...")
    
    try:
        web_acls = list_web_acls(waf_client, scope)
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        print(f"\nError: Failed to fetch Web ACLs")
        print(f"Error Code: {error_code}")
        print(f"Details: {error_msg}")
        return None, None
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        return None, None
    except Exception as e:
        print(f"\nUnexpected error while fetching Web ACLs: {e}")
        return None, None

    if not web_acls:
        print("No Web ACLs found.")
        print(f"Scope: {scope}")
        print("\nPossible reasons:")
        print("  - No Web ACLs exist in this scope")
        print("  - Web ACLs exist in a different region")
        print("  - Insufficient permissions to list Web ACLs")
        return None, None
    
    # Validate Web ACL data structure
    valid_web_acls = []
    for i, acl in enumerate(web_acls):
        if not isinstance(acl, dict):
            print(f"Warning: Skipping invalid Web ACL at index {i} (not a dict)")
            continue
        if 'Name' not in acl or 'Id' not in acl:
            print(f"Warning: Skipping Web ACL at index {i} (missing Name or Id)")
            continue
        valid_web_acls.append(acl)
    
    if not valid_web_acls:
        print("\nError: No valid Web ACLs found in response")
        print("All Web ACLs are missing required fields (Name, Id)")
        return None, None

    print(f"\nAvailable Web ACLs ({len(valid_web_acls)}):")
    print("-" * 80)
    for i, acl in enumerate(valid_web_acls, 1):
        print(f"{i}. {acl.get('Name', 'N/A')}")
        print(f"   ID: {acl.get('Id', 'N/A')}")
        if 'ARN' in acl:
            print(f"   ARN: {acl['ARN']}")
        if 'Description' in acl and acl['Description']:
            desc = acl['Description'][:60] + '...' if len(acl['Description']) > 60 else acl['Description']
            print(f"   Description: {desc}")
        print()

    max_attempts = 5
    attempts = 0
    
    while attempts < max_attempts:
        try:
            user_input = input(f"Select a Web ACL (1-{len(valid_web_acls)}) or 'q' to quit: ").strip()
            
            if user_input.lower() in ['q', 'quit', 'exit']:
                print("Selection cancelled.")
                return None, None
            
            choice = int(user_input)
            
            if 1 <= choice <= len(valid_web_acls):
                selected = valid_web_acls[choice - 1]
                print(f"\nSelected: {selected['Name']}")
                return selected['Name'], selected['Id']
            else:
                attempts += 1
                print(f"Invalid selection. Please enter a number between 1 and {len(valid_web_acls)}.")
                if attempts < max_attempts:
                    print(f"Attempts remaining: {max_attempts - attempts}")
                    
        except ValueError:
            attempts += 1
            print("Invalid input. Please enter a valid number.")
            if attempts < max_attempts:
                print(f"Attempts remaining: {max_attempts - attempts}")
        except KeyboardInterrupt:
            print("\n\nSelection cancelled by user.")
            return None, None
        except EOFError:
            print("\n\nEnd of input detected.")
            return None, None
    
    print(f"\nMaximum attempts ({max_attempts}) reached. Selection cancelled.")
    return None, None


def get_web_acl_associated_resources(waf_client, web_acl_arn: str) -> List[str]:
    """Get resources associated with a Web ACL."""
    try:
        response = waf_client.list_resources_for_web_acl(WebACLArn=web_acl_arn)
        return response.get('ResourceArns', [])
    except ClientError as e:
        print(f"Warning: Could not list associated resources: {e}")
        return []


# ============================================================
# Export Functions
# ============================================================

def export_rule_group_rules(rule_group_response: dict) -> dict:
    """Export rule group rules for JSON editor."""
    # Validate input
    if not rule_group_response:
        print("Warning: Empty rule group response provided")
        return {"Rules": []}
    
    if not isinstance(rule_group_response, dict):
        print(f"Warning: Invalid rule group response type: {type(rule_group_response).__name__}")
        return {"Rules": []}
    
    # Extract rule group
    rule_group = rule_group_response.get('RuleGroup')
    if not rule_group:
        print("Warning: Response missing 'RuleGroup' key")
        print(f"Available keys: {list(rule_group_response.keys())}")
        return {"Rules": []}
    
    if not isinstance(rule_group, dict):
        print(f"Warning: RuleGroup is not a dict: {type(rule_group).__name__}")
        return {"Rules": []}
    
    # Extract rules
    rules = rule_group.get('Rules', [])
    if not isinstance(rules, list):
        print(f"Warning: Rules is not a list: {type(rules).__name__}")
        rules = []
    
    return {"Rules": rules}


def export_full_rule_group(rule_group_response: dict) -> dict:
    """Export full rule group config."""
    # Validate input
    if not rule_group_response:
        raise ValueError("Empty rule group response provided")
    
    if not isinstance(rule_group_response, dict):
        raise TypeError(f"Invalid rule group response type: {type(rule_group_response).__name__}, expected dict")
    
    # Extract rule group
    rule_group = rule_group_response.get('RuleGroup')
    if not rule_group:
        raise ValueError(f"Response missing 'RuleGroup' key. Available keys: {list(rule_group_response.keys())}")
    
    if not isinstance(rule_group, dict):
        raise TypeError(f"RuleGroup is not a dict: {type(rule_group).__name__}")
    
    # Validate required fields
    required_fields = ['Name', 'Id', 'ARN']
    missing_fields = [field for field in required_fields if field not in rule_group]
    if missing_fields:
        print(f"Warning: Rule group missing required fields: {', '.join(missing_fields)}")
    
    lock_token = rule_group_response.get('LockToken', '')

    export_data = {
        "RuleGroup": {
            "Name": rule_group.get('Name'),
            "Id": rule_group.get('Id'),
            "ARN": rule_group.get('ARN'),
            "Capacity": rule_group.get('Capacity'),
            "Rules": rule_group.get('Rules', []),
            "VisibilityConfig": rule_group.get('VisibilityConfig'),
            "Description": rule_group.get('Description', ''),
        },
        "LockToken": lock_token
    }
    
    # Validate rules structure
    rules = export_data['RuleGroup']['Rules']
    if not isinstance(rules, list):
        print(f"Warning: Rules is not a list: {type(rules).__name__}, converting to empty list")
        export_data['RuleGroup']['Rules'] = []

    # Add optional fields
    if rule_group.get('CustomResponseBodies'):
        export_data['RuleGroup']['CustomResponseBodies'] = rule_group['CustomResponseBodies']
    if rule_group.get('LabelNamespace'):
        export_data['RuleGroup']['LabelNamespace'] = rule_group['LabelNamespace']

    return export_data


def export_web_acl_rules(web_acl_response: dict) -> dict:
    """Export Web ACL rules for JSON editor."""
    # Validate input
    if not web_acl_response:
        print("Warning: Empty Web ACL response provided")
        return {"Rules": []}
    
    if not isinstance(web_acl_response, dict):
        print(f"Warning: Invalid Web ACL response type: {type(web_acl_response).__name__}")
        return {"Rules": []}
    
    # Extract Web ACL
    web_acl = web_acl_response.get('WebACL')
    if not web_acl:
        print("Warning: Response missing 'WebACL' key")
        print(f"Available keys: {list(web_acl_response.keys())}")
        return {"Rules": []}
    
    if not isinstance(web_acl, dict):
        print(f"Warning: WebACL is not a dict: {type(web_acl).__name__}")
        return {"Rules": []}
    
    # Extract rules
    rules = web_acl.get('Rules', [])
    if not isinstance(rules, list):
        print(f"Warning: Rules is not a list: {type(rules).__name__}")
        rules = []
    
    return {"Rules": rules}


def export_full_web_acl(web_acl_response: dict) -> dict:
    """Export full Web ACL config."""
    # Validate input
    if not web_acl_response:
        raise ValueError("Empty Web ACL response provided")
    
    if not isinstance(web_acl_response, dict):
        raise TypeError(f"Invalid Web ACL response type: {type(web_acl_response).__name__}, expected dict")
    
    # Extract Web ACL
    web_acl = web_acl_response.get('WebACL')
    if not web_acl:
        raise ValueError(f"Response missing 'WebACL' key. Available keys: {list(web_acl_response.keys())}")
    
    if not isinstance(web_acl, dict):
        raise TypeError(f"WebACL is not a dict: {type(web_acl).__name__}")
    
    # Validate required fields
    required_fields = ['Name', 'Id', 'ARN', 'DefaultAction']
    missing_fields = [field for field in required_fields if field not in web_acl]
    if missing_fields:
        print(f"Warning: Web ACL missing required fields: {', '.join(missing_fields)}")
    
    lock_token = web_acl_response.get('LockToken', '')

    export_data = {
        "WebACL": {
            "Name": web_acl.get('Name'),
            "Id": web_acl.get('Id'),
            "ARN": web_acl.get('ARN'),
            "DefaultAction": web_acl.get('DefaultAction'),
            "Rules": web_acl.get('Rules', []),
            "VisibilityConfig": web_acl.get('VisibilityConfig'),
            "Description": web_acl.get('Description', ''),
            "Capacity": web_acl.get('Capacity'),
        },
        "LockToken": lock_token
    }
    
    # Validate rules structure
    rules = export_data['WebACL']['Rules']
    if not isinstance(rules, list):
        print(f"Warning: Rules is not a list: {type(rules).__name__}, converting to empty list")
        export_data['WebACL']['Rules'] = []

    # Add optional fields
    optional_fields = [
        'CustomResponseBodies', 'CaptchaConfig', 'ChallengeConfig',
        'TokenDomains', 'AssociationConfig'
    ]
    for field in optional_fields:
        if web_acl.get(field):
            export_data['WebACL'][field] = web_acl[field]

    # Pre/Post processing rules
    if web_acl.get('PreProcessFirewallManagerRuleGroups'):
        export_data['WebACL']['PreProcessFirewallManagerRuleGroups'] = web_acl[
            'PreProcessFirewallManagerRuleGroups']
    if web_acl.get('PostProcessFirewallManagerRuleGroups'):
        export_data['WebACL']['PostProcessFirewallManagerRuleGroups'] = web_acl[
            'PostProcessFirewallManagerRuleGroups']

    return export_data


def export_all(waf_client, scope: str, region: str) -> dict:
    """Export ALL rule groups and Web ACLs."""
    import datetime
    
    export_data = {
        "ExportMetadata": {
            "Scope": scope,
            "Region": region,
            "ExportType": "full_waf_export",
            "ExportTimestamp": datetime.datetime.utcnow().isoformat() + 'Z'
        },
        "RuleGroups": [],
        "WebACLs": [],
        "ExportErrors": {
            "RuleGroups": [],
            "WebACLs": []
        }
    }

    # Export all rule groups
    print("Fetching rule groups...")
    try:
        rule_groups = list_rule_groups(waf_client, scope)
        print(f"Found {len(rule_groups)} rule groups")
    except Exception as e:
        error_msg = f"Failed to list rule groups: {e}"
        print(f"Error: {error_msg}")
        export_data['ExportErrors']['RuleGroups'].append({
            "Operation": "list_rule_groups",
            "Error": str(e)
        })
        rule_groups = []
    
    successful_rg = 0
    failed_rg = 0
    
    for i, rg in enumerate(rule_groups, 1):
        rg_name = rg.get('Name', f'Unknown-{i}')
        rg_id = rg.get('Id', 'unknown')
        
        print(f"  [{i}/{len(rule_groups)}] Exporting rule group: {rg_name}")
        
        try:
            # Validate rule group structure
            if not isinstance(rg, dict):
                raise ValueError(f"Invalid rule group structure at index {i}")
            if 'Name' not in rg or 'Id' not in rg:
                raise ValueError(f"Rule group missing Name or Id at index {i}")
            
            response = get_rule_group(waf_client, rg['Name'], scope, rg['Id'])
            exported = export_full_rule_group(response)
            export_data['RuleGroups'].append(exported)
            successful_rg += 1
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_msg = e.response.get('Error', {}).get('Message', str(e))
            print(f"    Warning: Failed to export - [{error_code}] {error_msg}")
            export_data['ExportErrors']['RuleGroups'].append({
                "Name": rg_name,
                "Id": rg_id,
                "ErrorCode": error_code,
                "ErrorMessage": error_msg
            })
            failed_rg += 1
            
        except (ValueError, TypeError) as e:
            print(f"    Warning: Failed to export - {e}")
            export_data['ExportErrors']['RuleGroups'].append({
                "Name": rg_name,
                "Id": rg_id,
                "ErrorCode": "ValidationError",
                "ErrorMessage": str(e)
            })
            failed_rg += 1
            
        except KeyboardInterrupt:
            print("\n\nExport cancelled by user.")
            print(f"Exported {successful_rg} rule groups before cancellation.")
            raise
            
        except Exception as e:
            print(f"    Warning: Unexpected error - {e}")
            export_data['ExportErrors']['RuleGroups'].append({
                "Name": rg_name,
                "Id": rg_id,
                "ErrorCode": "UnexpectedError",
                "ErrorMessage": str(e)
            })
            failed_rg += 1
    
    print(f"\nRule Groups: {successful_rg} successful, {failed_rg} failed")

    # Export all Web ACLs
    print("\nFetching Web ACLs...")
    try:
        web_acls = list_web_acls(waf_client, scope)
        print(f"Found {len(web_acls)} Web ACLs")
    except Exception as e:
        error_msg = f"Failed to list Web ACLs: {e}"
        print(f"Error: {error_msg}")
        export_data['ExportErrors']['WebACLs'].append({
            "Operation": "list_web_acls",
            "Error": str(e)
        })
        web_acls = []
    
    successful_acl = 0
    failed_acl = 0
    
    for i, acl in enumerate(web_acls, 1):
        acl_name = acl.get('Name', f'Unknown-{i}')
        acl_id = acl.get('Id', 'unknown')
        acl_arn = acl.get('ARN', 'unknown')
        
        print(f"  [{i}/{len(web_acls)}] Exporting Web ACL: {acl_name}")
        
        try:
            # Validate Web ACL structure
            if not isinstance(acl, dict):
                raise ValueError(f"Invalid Web ACL structure at index {i}")
            if 'Name' not in acl or 'Id' not in acl:
                raise ValueError(f"Web ACL missing Name or Id at index {i}")
            
            response = get_web_acl(waf_client, acl['Name'], scope, acl['Id'])
            acl_export = export_full_web_acl(response)

            # Add associated resources
            try:
                resources = get_web_acl_associated_resources(waf_client, acl_arn)
                acl_export['AssociatedResources'] = resources
                if resources:
                    print(f"    Found {len(resources)} associated resources")
            except Exception as e:
                print(f"    Warning: Could not fetch associated resources: {e}")
                acl_export['AssociatedResources'] = []

            export_data['WebACLs'].append(acl_export)
            successful_acl += 1
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_msg = e.response.get('Error', {}).get('Message', str(e))
            print(f"    Warning: Failed to export - [{error_code}] {error_msg}")
            export_data['ExportErrors']['WebACLs'].append({
                "Name": acl_name,
                "Id": acl_id,
                "ARN": acl_arn,
                "ErrorCode": error_code,
                "ErrorMessage": error_msg
            })
            failed_acl += 1
            
        except (ValueError, TypeError) as e:
            print(f"    Warning: Failed to export - {e}")
            export_data['ExportErrors']['WebACLs'].append({
                "Name": acl_name,
                "Id": acl_id,
                "ARN": acl_arn,
                "ErrorCode": "ValidationError",
                "ErrorMessage": str(e)
            })
            failed_acl += 1
            
        except KeyboardInterrupt:
            print("\n\nExport cancelled by user.")
            print(f"Exported {successful_acl} Web ACLs before cancellation.")
            raise
            
        except Exception as e:
            print(f"    Warning: Unexpected error - {e}")
            export_data['ExportErrors']['WebACLs'].append({
                "Name": acl_name,
                "Id": acl_id,
                "ARN": acl_arn,
                "ErrorCode": "UnexpectedError",
                "ErrorMessage": str(e)
            })
            failed_acl += 1
    
    print(f"\nWeb ACLs: {successful_acl} successful, {failed_acl} failed")
    
    # Clean up empty error lists
    if not export_data['ExportErrors']['RuleGroups']:
        del export_data['ExportErrors']['RuleGroups']
    if not export_data['ExportErrors']['WebACLs']:
        del export_data['ExportErrors']['WebACLs']
    if not export_data['ExportErrors']:
        del export_data['ExportErrors']

    return export_data


# ============================================================
# Import / Extract Functions
# ============================================================

def extract_rules_from_json(data: dict) -> Tuple[List[Dict], Optional[Dict], Optional[Dict], Optional[str]]:
    """
    Extract rules from various JSON formats.
    
    Returns:
        Tuple of (rules, visibility_config, custom_response_bodies, description)
    
    Raises:
        ValueError: If data format is invalid
        TypeError: If data type is incorrect
    """
    # Validate input type
    if data is None:
        raise ValueError("Input data is None")
    
    if not isinstance(data, (dict, list)):
        raise TypeError(f"Invalid JSON format - expected dict or list, got {type(data).__name__}")

    # Check for valid structure
    if isinstance(data, dict):
        valid_keys = {'Rules', 'RuleGroup', 'WebACL'}
        has_valid_key = any(key in data for key in valid_keys)
        
        if not has_valid_key:
            available_keys = list(data.keys())
            raise ValueError(
                f"Invalid JSON structure. Expected one of: 'Rules', 'RuleGroup', 'WebACL'. "
                f"Found keys: {available_keys}"
            )

    rules = []
    visibility_config = None
    custom_response_bodies = None
    description = None

    try:
        # Format 1: Just rules array {"Rules": [...]}
        if isinstance(data, dict) and 'Rules' in data:
            rules = data['Rules']
            if not isinstance(rules, list):
                raise TypeError(f"'Rules' must be a list, got {type(rules).__name__}")
                
        # Format 2: Full RuleGroup export {"RuleGroup": {...}}
        elif isinstance(data, dict) and 'RuleGroup' in data:
            rg = data['RuleGroup']
            if not isinstance(rg, dict):
                raise TypeError(f"'RuleGroup' must be a dict, got {type(rg).__name__}")
            
            rules = rg.get('Rules', [])
            if not isinstance(rules, list):
                raise TypeError(f"'RuleGroup.Rules' must be a list, got {type(rules).__name__}")
            
            visibility_config = rg.get('VisibilityConfig')
            if visibility_config is not None and not isinstance(visibility_config, dict):
                print(f"Warning: VisibilityConfig is not a dict, ignoring")
                visibility_config = None
            
            custom_response_bodies = rg.get('CustomResponseBodies')
            if custom_response_bodies is not None and not isinstance(custom_response_bodies, dict):
                print(f"Warning: CustomResponseBodies is not a dict, ignoring")
                custom_response_bodies = None
            
            description = rg.get('Description')
            if description is not None and not isinstance(description, str):
                print(f"Warning: Description is not a string, converting")
                description = str(description)
                
        # Format 3: Full WebACL Export {"WebACL": {...}}
        elif isinstance(data, dict) and 'WebACL' in data:
            acl = data['WebACL']
            if not isinstance(acl, dict):
                raise TypeError(f"'WebACL' must be a dict, got {type(acl).__name__}")
            
            rules = acl.get('Rules', [])
            if not isinstance(rules, list):
                raise TypeError(f"'WebACL.Rules' must be a list, got {type(rules).__name__}")
            
            visibility_config = acl.get('VisibilityConfig')
            if visibility_config is not None and not isinstance(visibility_config, dict):
                print(f"Warning: VisibilityConfig is not a dict, ignoring")
                visibility_config = None
            
            custom_response_bodies = acl.get('CustomResponseBodies')
            if custom_response_bodies is not None and not isinstance(custom_response_bodies, dict):
                print(f"Warning: CustomResponseBodies is not a dict, ignoring")
                custom_response_bodies = None
            
            description = acl.get('Description')
            if description is not None and not isinstance(description, str):
                print(f"Warning: Description is not a string, converting")
                description = str(description)
                
        # Format 4: Direct rules array [...]
        elif isinstance(data, list):
            rules = data
            
        # Validate rules structure
        if not isinstance(rules, list):
            raise TypeError(f"Extracted rules must be a list, got {type(rules).__name__}")
        
        # Validate each rule has required structure
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise TypeError(f"Rule at index {i} must be a dict, got {type(rule).__name__}")
            if 'Name' not in rule:
                raise ValueError(f"Rule at index {i} missing required 'Name' field")
            if 'Priority' not in rule:
                raise ValueError(f"Rule at index {i} ('{rule.get('Name', 'unknown')}') missing required 'Priority' field")
            if 'Statement' not in rule:
                raise ValueError(f"Rule at index {i} ('{rule.get('Name', 'unknown')}') missing required 'Statement' field")
        
        return rules, visibility_config, custom_response_bodies, description
        
    except (KeyError, AttributeError) as e:
        raise ValueError(f"Error extracting rules from JSON: {e}")
    except Exception as e:
        if isinstance(e, (ValueError, TypeError)):
            raise
        raise ValueError(f"Unexpected error extracting rules: {e}")


def extract_web_acl_config(data: dict) -> Dict:
    """
    Extract full Web ACL configuration from JSON.
    
    Raises:
        ValueError: If data format is invalid
        TypeError: If data type is incorrect
    """
    # Validate input
    if data is None:
        raise ValueError("Input data is None")
    
    if not isinstance(data, dict):
        raise TypeError(f"Invalid input type - expected dict, got {type(data).__name__}")
    
    config = {
        'rules': [],
        'default_action': None,
        'visibility_config': None,
        'custom_response_bodies': None,
        'description': '',
        'captcha_config': None,
        'challenge_config': None,
        'token_domains': None,
        'association_config': None,
    }

    try:
        if 'WebACL' in data:
            acl = data['WebACL']
            if not isinstance(acl, dict):
                raise TypeError(f"'WebACL' must be a dict, got {type(acl).__name__}")
            
            # Extract rules
            rules = acl.get('Rules', [])
            if not isinstance(rules, list):
                raise TypeError(f"'WebACL.Rules' must be a list, got {type(rules).__name__}")
            config['rules'] = rules
            
            # Extract default action
            default_action = acl.get('DefaultAction')
            if default_action is not None:
                if not isinstance(default_action, dict):
                    raise TypeError(f"'DefaultAction' must be a dict, got {type(default_action).__name__}")
                # Validate default action has either Allow or Block
                if 'Allow' not in default_action and 'Block' not in default_action:
                    raise ValueError("'DefaultAction' must contain either 'Allow' or 'Block'")
            config['default_action'] = default_action
            
            # Extract visibility config
            visibility_config = acl.get('VisibilityConfig')
            if visibility_config is not None and not isinstance(visibility_config, dict):
                print(f"Warning: VisibilityConfig is not a dict, ignoring")
                visibility_config = None
            config['visibility_config'] = visibility_config
            
            # Extract custom response bodies
            custom_response_bodies = acl.get('CustomResponseBodies')
            if custom_response_bodies is not None and not isinstance(custom_response_bodies, dict):
                print(f"Warning: CustomResponseBodies is not a dict, ignoring")
                custom_response_bodies = None
            config['custom_response_bodies'] = custom_response_bodies
            
            # Extract description
            description = acl.get('Description', '')
            if description and not isinstance(description, str):
                print(f"Warning: Description is not a string, converting")
                description = str(description)
            config['description'] = description
            
            # Extract optional configs
            captcha_config = acl.get('CaptchaConfig')
            if captcha_config is not None and not isinstance(captcha_config, dict):
                print(f"Warning: CaptchaConfig is not a dict, ignoring")
                captcha_config = None
            config['captcha_config'] = captcha_config
            
            challenge_config = acl.get('ChallengeConfig')
            if challenge_config is not None and not isinstance(challenge_config, dict):
                print(f"Warning: ChallengeConfig is not a dict, ignoring")
                challenge_config = None
            config['challenge_config'] = challenge_config
            
            token_domains = acl.get('TokenDomains')
            if token_domains is not None and not isinstance(token_domains, list):
                print(f"Warning: TokenDomains is not a list, ignoring")
                token_domains = None
            config['token_domains'] = token_domains
            
            association_config = acl.get('AssociationConfig')
            if association_config is not None and not isinstance(association_config, dict):
                print(f"Warning: AssociationConfig is not a dict, ignoring")
                association_config = None
            config['association_config'] = association_config
            
        elif 'Rules' in data:
            rules = data['Rules']
            if not isinstance(rules, list):
                raise TypeError(f"'Rules' must be a list, got {type(rules).__name__}")
            config['rules'] = rules
        else:
            raise ValueError("Input must contain either 'WebACL' or 'Rules' key")
        
        # Validate rules structure
        for i, rule in enumerate(config['rules']):
            if not isinstance(rule, dict):
                raise TypeError(f"Rule at index {i} must be a dict, got {type(rule).__name__}")
            if 'Name' not in rule:
                raise ValueError(f"Rule at index {i} missing required 'Name' field")
        
        # Ensure default_action has a value
        if config['default_action'] is None:
            config['default_action'] = {'Allow': {}}
            print("Info: No DefaultAction specified, using Allow")

        return config
        
    except (KeyError, AttributeError) as e:
        raise ValueError(f"Error extracting Web ACL config: {e}")
    except Exception as e:
        if isinstance(e, (ValueError, TypeError)):
            raise
        raise ValueError(f"Unexpected error extracting Web ACL config: {e}")


# ============================================================
# Create / Update Functions
# ============================================================

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
    
    Raises:
        ValueError: If parameters are invalid
        ClientError: If AWS API call fails
    """
    # Validate required parameters
    if not name or not isinstance(name, str):
        raise ValueError(f"Invalid name: must be non-empty string, got {type(name).__name__}")
    
    if len(name) > 128:
        raise ValueError(f"Name too long: {len(name)} characters (max 128)")
    
    if scope not in ['REGIONAL', 'CLOUDFRONT']:
        raise ValueError(f"Invalid scope: must be 'REGIONAL' or 'CLOUDFRONT', got '{scope}'")
    
    if not isinstance(capacity, int) or capacity <= 0:
        raise ValueError(f"Invalid capacity: must be positive integer, got {capacity}")
    
    if capacity > 5000:
        raise ValueError(f"Capacity too high: {capacity} (max 5000)")
    
    if not isinstance(rules, list):
        raise TypeError(f"Rules must be a list, got {type(rules).__name__}")
    
    if len(rules) == 0:
        raise ValueError("Rules list cannot be empty")
    
    # Validate rules structure
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise TypeError(f"Rule at index {i} must be a dict")
        if 'Name' not in rule:
            raise ValueError(f"Rule at index {i} missing 'Name'")
        if 'Priority' not in rule:
            raise ValueError(f"Rule at index {i} ('{rule['Name']}') missing 'Priority'")
        if 'Statement' not in rule:
            raise ValueError(f"Rule at index {i} ('{rule['Name']}') missing 'Statement'")
    
    # Default visibility config
    if visibility_config is None:
        metric_name = name.replace('-', '').replace('_', '')[:128]
        visibility_config = {
            'SampledRequestsEnabled': True,
            'CloudWatchMetricsEnabled': True,
            'MetricName': metric_name
        }
    else:
        # Validate visibility config
        if not isinstance(visibility_config, dict):
            raise TypeError(f"VisibilityConfig must be a dict, got {type(visibility_config).__name__}")
        required_fields = ['SampledRequestsEnabled', 'CloudWatchMetricsEnabled', 'MetricName']
        missing = [f for f in required_fields if f not in visibility_config]
        if missing:
            raise ValueError(f"VisibilityConfig missing required fields: {', '.join(missing)}")

    # Validate optional parameters
    if description and not isinstance(description, str):
        raise TypeError(f"Description must be a string, got {type(description).__name__}")
    
    if description and len(description) > 256:
        raise ValueError(f"Description too long: {len(description)} characters (max 256)")
    
    if tags is not None:
        if not isinstance(tags, list):
            raise TypeError(f"Tags must be a list, got {type(tags).__name__}")
        for i, tag in enumerate(tags):
            if not isinstance(tag, dict):
                raise TypeError(f"Tag at index {i} must be a dict")
            if 'Key' not in tag or 'Value' not in tag:
                raise ValueError(f"Tag at index {i} missing 'Key' or 'Value'")
    
    if custom_response_bodies is not None and not isinstance(custom_response_bodies, dict):
        raise TypeError(f"CustomResponseBodies must be a dict, got {type(custom_response_bodies).__name__}")

    # Build parameters
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
    
    # Create rule group
    try:
        response = waf_client.create_rule_group(**params)
        
        # Validate response
        if 'Summary' not in response:
            print("Warning: Response missing 'Summary' key")
        
        return response
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        
        # Provide specific error messages
        if error_code == 'WAFDuplicateItemException':
            print(f"Error: Rule group '{name}' already exists")
            print(f"Details: {error_msg}")
            print("Use a different name or delete the existing rule group first.")
        elif error_code == 'WAFLimitsExceededException':
            print(f"Error: WAF limits exceeded")
            print(f"Details: {error_msg}")
            print("You may have reached the maximum number of rule groups.")
        elif error_code == 'WAFInvalidParameterException':
            print(f"Error: Invalid parameter")
            print(f"Details: {error_msg}")
            print("Check rule structure and parameter values.")
        elif error_code == 'WAFInvalidOperationException':
            print(f"Error: Invalid operation")
            print(f"Details: {error_msg}")
        elif error_code == 'WAFSubscriptionNotFoundException':
            print(f"Error: WAF subscription not found")
            print(f"Details: {error_msg}")
            print("Ensure you have an active WAF subscription.")
        elif error_code in ['AccessDeniedException', 'WAFAccessDeniedException']:
            print(f"Error: Access denied")
            print(f"Details: {error_msg}")
            print("Check your IAM permissions for wafv2:CreateRuleGroup")
        else:
            print(f"Error creating rule group: [{error_code}] {error_msg}")
        
        raise
    
    except Exception as e:
        print(f"Unexpected error creating rule group: {e}")
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
    
    Raises:
        ValueError: If parameters are invalid
        ClientError: If AWS API call fails
    """
    # Validate required parameters
    if not name or not isinstance(name, str):
        raise ValueError(f"Invalid name: must be non-empty string, got {type(name).__name__}")
    
    if len(name) > 128:
        raise ValueError(f"Name too long: {len(name)} characters (max 128)")
    
    if scope not in ['REGIONAL', 'CLOUDFRONT']:
        raise ValueError(f"Invalid scope: must be 'REGIONAL' or 'CLOUDFRONT', got '{scope}'")
    
    if not rule_group_id or not isinstance(rule_group_id, str):
        raise ValueError(f"Invalid rule_group_id: must be non-empty string")
    
    if not lock_token or not isinstance(lock_token, str):
        raise ValueError(f"Invalid lock_token: must be non-empty string")
    
    if not isinstance(rules, list):
        raise TypeError(f"Rules must be a list, got {type(rules).__name__}")
    
    # Note: Empty rules list is allowed for updates (removes all rules)
    
    # Validate rules structure
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise TypeError(f"Rule at index {i} must be a dict")
        if 'Name' not in rule:
            raise ValueError(f"Rule at index {i} missing 'Name'")
        if 'Priority' not in rule:
            raise ValueError(f"Rule at index {i} ('{rule['Name']}') missing 'Priority'")
        if 'Statement' not in rule:
            raise ValueError(f"Rule at index {i} ('{rule['Name']}') missing 'Statement'")
    
    # Default visibility config
    if visibility_config is None:
        metric_name = name.replace('-', '').replace('_', '')[:128]
        visibility_config = {
            'SampledRequestsEnabled': True,
            'CloudWatchMetricsEnabled': True,
            'MetricName': metric_name
        }
    else:
        # Validate visibility config
        if not isinstance(visibility_config, dict):
            raise TypeError(f"VisibilityConfig must be a dict, got {type(visibility_config).__name__}")
        required_fields = ['SampledRequestsEnabled', 'CloudWatchMetricsEnabled', 'MetricName']
        missing = [f for f in required_fields if f not in visibility_config]
        if missing:
            raise ValueError(f"VisibilityConfig missing required fields: {', '.join(missing)}")
    
    # Validate optional parameters
    if description and not isinstance(description, str):
        raise TypeError(f"Description must be a string, got {type(description).__name__}")
    
    if description and len(description) > 256:
        raise ValueError(f"Description too long: {len(description)} characters (max 256)")
    
    if custom_response_bodies is not None and not isinstance(custom_response_bodies, dict):
        raise TypeError(f"CustomResponseBodies must be a dict, got {type(custom_response_bodies).__name__}")
    
    # Build parameters
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
    
    # Update rule group
    try:
        response = waf_client.update_rule_group(**params)
        
        # Validate response
        if 'NextLockToken' not in response:
            print("Warning: Response missing 'NextLockToken' key")
        
        return response
        
    except ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', 'Unknown')
        error_msg = e.response.get('Error', {}).get('Message', str(e))
        
        # Provide specific error messages
        if error_code == 'WAFNonexistentItemException':
            print(f"Error: Rule group '{name}' not found")
            print(f"Details: {error_msg}")
            print("The rule group may have been deleted.")
        elif error_code == 'WAFOptimisticLockException':
            print(f"Error: Rule group was modified by another process")
            print(f"Details: {error_msg}")
            print("Please fetch the latest version and try again.")
        elif error_code == 'WAFInvalidParameterException':
            print(f"Error: Invalid parameter")
            print(f"Details: {error_msg}")
            print("Check rule structure and parameter values.")
        elif error_code == 'WAFLimitsExceededException':
            print(f"Error: WAF limits exceeded")
            print(f"Details: {error_msg}")
            print("The new rules may exceed capacity or other limits.")
        elif error_code == 'WAFInvalidOperationException':
            print(f"Error: Invalid operation")
            print(f"Details: {error_msg}")
        elif error_code == 'WAFUnavailableEntityException':
            print(f"Error: Referenced entity unavailable")
            print(f"Details: {error_msg}")
            print("One or more rules reference entities that are unavailable.")
        elif error_code in ['AccessDeniedException', 'WAFAccessDeniedException']:
            print(f"Error: Access denied")
            print(f"Details: {error_msg}")
            print("Check your IAM permissions for wafv2:UpdateRuleGroup")
        else:
            print(f"Error updating rule group: [{error_code}] {error_msg}")
        
        raise
    
    except Exception as e:
        print(f"Unexpected error updating rule group: {e}")
        raise


def create_web_acl(
        waf_client, name: str, scope: str, rules: List[Dict],
        default_action: Dict, description: str = '',
        visibility_config: Optional[Dict] = None,
        tags: Optional[List[Dict]] = None,
        custom_response_bodies: Optional[Dict] = None,
        captcha_config: Optional[Dict] = None,
        challenge_config: Optional[Dict] = None,
        token_domains: Optional[List[str]] = None,
        association_config: Optional[Dict] = None
) -> Dict:
    """Create a new Web ACL."""
    if visibility_config is None:
        visibility_config = {
            'SampledRequestsEnabled': True,
            'CloudWatchMetricsEnabled': True,
            'MetricName': name.replace('-', '').replace('_', '')[:128]
        }

    params = {
        'Name': name, 'Scope': scope, 'DefaultAction': default_action,
        'Rules': rules, 'VisibilityConfig': visibility_config
    }

    if description:
        params['Description'] = description
    if tags:
        params['Tags'] = tags
    if custom_response_bodies:
        params['CustomResponseBodies'] = custom_response_bodies
    if captcha_config:
        params['CaptchaConfig'] = captcha_config
    if challenge_config:
        params['ChallengeConfig'] = challenge_config
    if token_domains:
        params['TokenDomains'] = token_domains
    if association_config:
        params['AssociationConfig'] = association_config

    try:
        return waf_client.create_web_acl(**params)
    except ClientError as e:
        print(f"Error creating Web ACL: {e}")
        raise


def update_web_acl(
        waf_client, name: str, scope: str, web_acl_id: str,
        rules: List[Dict], default_action: Dict, lock_token: str,
        description: str = '', visibility_config: Optional[Dict] = None,
        custom_response_bodies: Optional[Dict] = None,
        captcha_config: Optional[Dict] = None,
        challenge_config: Optional[Dict] = None,
        token_domains: Optional[List[str]] = None,
        association_config: Optional[Dict] = None
) -> Dict:
    """Update an existing Web ACL."""
    if visibility_config is None:
        visibility_config = {
            'SampledRequestsEnabled': True,
            'CloudWatchMetricsEnabled': True,
            'MetricName': name.replace('-', '').replace('_', '')[:128]
        }

    params = {
        'Name': name, 'Scope': scope, 'Id': web_acl_id,
        'DefaultAction': default_action, 'Rules': rules,
        'VisibilityConfig': visibility_config, 'LockToken': lock_token
    }

    if description:
        params['Description'] = description
    if custom_response_bodies:
        params['CustomResponseBodies'] = custom_response_bodies
    if captcha_config:
        params['CaptchaConfig'] = captcha_config
    if challenge_config:
        params['ChallengeConfig'] = challenge_config
    if token_domains:
        params['TokenDomains'] = token_domains
    if association_config:
        params['AssociationConfig'] = association_config

    try:
        return waf_client.update_web_acl(**params)
    except ClientError as e:
        print(f"Error updating Web ACL: {e}")
        raise


# ============================================================
# ARN Remapping Utility
# ============================================================

def remap_arns(rules: List[Dict], arn_map: Dict[str, str]) -> List[Dict]:
    """
    Recursively remap ARNs in rules.
    Useful when moving between accounts/regions.

    arn_map: {"old_arn": "new_arn", ...}
    """
    rules_str = json.dumps(rules)
    for old_arn, new_arn in arn_map.items():
        rules_str = rules_str.replace(old_arn, new_arn)
    return json.loads(rules_str)


def load_arn_map(filename: str) -> Dict[str, str]:
    """Load ARN mapping from file."""
    data = load_from_file(filename)
    if not isinstance(data, dict):
        print("Error: ARN map must be a JSON object with old_arn: new_arn pairs")
        sys.exit(1)
    return data


# ============================================================
# Command Handlers
# ============================================================

def do_list(args):
    """Handle the list command."""
    validate_scope_required(args, 'list')
    
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)

    waf_client = get_waf_client(args.scope, args.region)

    resource_type = getattr(args, 'type', 'all')

    if resource_type in ['all', 'rule-groups', 'rg']:
        rule_groups = list_rule_groups(waf_client, args.scope)
        print(f"\nRule Groups ({args.scope} - {args.region}):")
        print("-" * 80)
        for rg in rule_groups:
            print(f"  Name: {rg['Name']}")
            print(f"  ID:   {rg['Id']}")
            print(f"  ARN:  {rg['ARN']}")
            print()
        if not rule_groups:
            print("  No rule groups found.\n")

    if resource_type in ['all', 'web-acls', 'waf']:
        web_acls = list_web_acls(waf_client, args.scope)
        print(f"\nWeb ACLs ({args.scope} - {args.region}):")
        print("-" * 80)
        for acl in web_acls:
            print(f"  Name: {acl['Name']}")
            print(f"  ID:   {acl['Id']}")
            print(f"  ARN:  {acl['ARN']}")
            print()
        if not web_acls:
            print("  No Web ACLs found.\n")


def do_export_rule_group(args):
    """Handle rule group export."""
    # Set AWS profile if specified
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)

    # Validate: either ARN or (scope + name + id) or (scope for interactive)
    has_arn = hasattr(args, 'arn') and args.arn
    has_name_id = hasattr(args, 'name') and args.name and hasattr(args, 'id') and args.id
    
    if not has_arn and not args.scope:
        print("Error: --scope is required when not using --arn")
        print("Choose: --scope REGIONAL or --scope CLOUDFRONT")
        sys.exit(1)

    if not has_name_id:
        print("Error: --name and --id are both required when not using --arn")
        sys.exit(1)

    if args.arn:
        waf_client = boto3.client('wafv2', region_name='us-east-1')
        if ':regional/' in args.arn:
            region = args.arn.split(':')[3]
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

        # Interactive or direct selection
        if args.name and args.id:
            rule_group_name = args.name
            rule_group_id = args.id
        else:
            rule_group_name, rule_group_id = interactive_select_rule_group(waf_client, args.scope)
            if not rule_group_name:
                return

        print(f"\nFetching rule group: {rule_group_name}")
        response = get_rule_group(waf_client, rule_group_name, args.scope, rule_group_id)

    # Determine output format
    if args.full:
        export_data = export_full_rule_group(response)
        default_suffix = "-rulegroup-full.json"
    else:
        export_data = export_rule_group_rules(response)
        default_suffix = "-rulegroup-rules.json"

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
    print(f"Capacity: {response.get('RuleGroup', {}).get('Capacity', 'N/A')}")

    # Save to file
    save_to_file(export_data, output_file)
    
    print(f"\n{'='*60}")
    print("To import into a new rule group:")
    print(f"  python {sys.argv[0]} create-rule-group --scope {args.scope or 'REGIONAL'} \\")
    print(f"      --region {args.region} --name NewRuleGroupName \\")
    print(f"      --input {output_file}")
    print('='*60)


def do_export_web_acl(args):
    """Handle Web ACL export."""
    validate_scope_required(args, 'export-web-acl')
    
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)

    waf_client = get_waf_client(args.scope, args.region)

    # Validate: either (name + id) or interactive selection
    has_name_id = hasattr(args, 'name') and args.name and hasattr(args, 'id') and args.id

    if has_name_id:
        web_acl_name = args.name
        web_acl_id = args.id
    else:
        web_acl_name, web_acl_id = interactive_select_web_acl(waf_client, args.scope)
        if not web_acl_name:
            return

    print(f"\nFetching Web ACL: {web_acl_name}")
    response = get_web_acl(waf_client, web_acl_name, args.scope, web_acl_id)

    if args.full:
        export_data = export_full_web_acl(response)
        default_suffix = "-webacl-full.json"

        # Include associated resources
        if not args.no_resources:
            web_acl_arn = response['WebACL']['ARN']
            print("Fetching associated resources...")
            resources = get_web_acl_associated_resources(waf_client, web_acl_arn)
            export_data['AssociatedResources'] = resources
            if resources:
                print(f"  Found {len(resources)} associated resources")
    else:
        export_data = export_web_acl_rules(response)
        default_suffix = "-webacl-rules.json"

    if args.output:
        output_file = args.output
    else:
        safe_name = web_acl_name.replace(' ', '-').replace('/', '-')
        output_file = f"{safe_name}{default_suffix}"

    rules = export_data.get('Rules', export_data.get('WebACL', {}).get('Rules', []))
    web_acl = response['WebACL']
    print(f"\nWeb ACL: {web_acl_name}")
    print(f"Total Rules: {len(rules)}")
    print(f"Capacity: {web_acl.get('Capacity', 'N/A')}")
    print(f"Default Action: {json.dumps(web_acl.get('DefaultAction', {}))}")

    # Summarize rule types
    rule_types = summarize_rules(rules)
    print(f"\nRule Summary:")
    for rule_type, count in rule_types.items():
        print(f"  {rule_type}: {count}")

    save_to_file(export_data, output_file)


def do_export_all(args):
    """Handle export-all command."""
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)

    validate_scope_required(args, 'export-all')

    waf_client = get_waf_client(args.scope, args.region)

    print(f"Exporting all WAF resources ({args.scope} - {args.region})...")
    export_data = export_all(waf_client, args.scope, args.region)

    if args.output:
        output_file = args.output
    else:
        output_file = f"waf-export-{args.scope.lower()}-{args.region}.json"

    print(f"\nExport Summary:")
    print(f"  Rule Groups: {len(export_data['RuleGroups'])}")
    print(f"  Web ACLs: {len(export_data['WebACLs'])}")

    save_to_file(export_data, output_file)


def do_create_rule_group(args):
    """Handle rule group creation."""
    # Validate required parameters upfront
    validate_scope_required(args, 'create-rule-group')
    validate_required_params(args, 'create-rule-group', ['name', 'input'])
    validate_file_exists(args.input, '--input')
    
    if args.arn_map:
        validate_file_exists(args.arn_map, '--arn-map')
    
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)

    # Load rules from file
    print(f"Loading rules from: {args.input}")
    data = load_from_file(args.input)

    try:
        rules, visibility_config, custom_response_bodies, description = extract_rules_from_json(data)
    except (ValueError, TypeError) as e:
        print(f"Error: Invalid rule data in input file: {e}")
        sys.exit(1)

    if not rules:
        print("Error: No rules found in the input file")
        sys.exit(1)

    # Apply ARN remapping if specified
    if args.arn_map:
        print(f"Loading ARN mapping from: {args.arn_map}")
        arn_map = load_arn_map(args.arn_map)
        rules = remap_arns(rules, arn_map)
        print(f"  Remapped {len(arn_map)} ARNs")

    if args.description:
        description = args.description

    waf_client = get_waf_client(args.scope, args.region)

    # Calculate or use provided capacity
    if args.capacity:
        capacity = args.capacity
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
    print(f"\n{'=' * 60}")
    print(f"Create Rule Group:")
    print(f"  Name: {args.name}")
    print(f"  Scope: {args.scope}")
    print(f"  Region: {args.region}")
    print(f"  Capacity: {capacity}")
    print(f"  Rules: {len(rules)}")
    print(f"  Description: {description or '(none)'}")
    if tags:
        print(f"  Tags: {tags}")
    print('='*60)

    if not confirm_action("Create this rule group?", args.yes):
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

        summary = response.get('Summary', {})
        print(f"\n✓ Rule group created successfully!")
        print(f"  Name: {summary.get('Name', 'N/A')}")
        print(f"  ID: {summary.get('Id', 'N/A')}")
        print(f"  ARN: {summary.get('ARN', 'N/A')}")

    except (ValueError, TypeError) as e:
        print(f"\nError: Invalid parameters for rule group creation: {e}")
        sys.exit(1)
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

def do_create_web_acl(args):
    """Handle Web ACL creation."""
    # Validate required parameters upfront
    validate_scope_required(args, 'create-web-acl')
    validate_required_params(args, 'create-web-acl', ['name', 'input'])
    validate_file_exists(args.input, '--input')
    
    if args.arn_map:
        validate_file_exists(args.arn_map, '--arn-map')
    
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)

    print(f"Loading Web ACL config from: {args.input}")
    data = load_from_file(args.input)

    try:
        config = extract_web_acl_config(data)
    except (ValueError, TypeError) as e:
        print(f"Error: Invalid Web ACL configuration in input file: {e}")
        sys.exit(1)
        
    rules = config['rules']

    if not rules:
        print("Warning: No rules found in input file. Creating empty Web ACL.")

    # Apply ARN remapping if specified
    if args.arn_map:
        print(f"Loading ARN mapping from: {args.arn_map}")
        arn_map = load_arn_map(args.arn_map)
        rules = remap_arns(rules, arn_map)
        print(f"  Remapped {len(arn_map)} ARNs")

    if args.description:
        config['description'] = args.description

    # Parse default action
    default_action = config['default_action']
    if args.default_action:
        if args.default_action.lower() == 'allow':
            default_action = {'Allow': {}}
        elif args.default_action.lower() == 'block':
            default_action = {'Block': {}}

    waf_client = get_waf_client(args.scope, args.region)

    tags = None
    if args.tags:
        tags = [{'Key': k, 'Value': v} for t in args.tags for k, v in [t.split('=', 1)]]

    # Summarize
    rule_types = summarize_rules(rules)

    print(f"\n{'=' * 60}")
    print(f"Create Web ACL:")
    print(f"  Name: {args.name}")
    print(f"  Scope: {args.scope}")
    print(f"  Region: {args.region}")
    print(f"  Default Action: {json.dumps(default_action)}")
    print(f"  Rules: {len(rules)}")
    for rule_type, count in rule_types.items():
        print(f"    {rule_type}: {count}")
    print(f"  Description: {config['description'] or '(none)'}")
    print(f"{'=' * 60}")

    if not confirm_action("Create this Web ACL?", args.yes):
        print("Aborted.")
        return

    print("\nCreating Web ACL...")
    try:
        response = create_web_acl(
            waf_client=waf_client,
            name=args.name,
            scope=args.scope,
            rules=rules,
            default_action=default_action,
            description=config['description'] or '',
            visibility_config=config['visibility_config'],
            tags=tags,
            custom_response_bodies=config['custom_response_bodies'],
            captcha_config=config['captcha_config'],
            challenge_config=config['challenge_config'],
            token_domains=config['token_domains'],
            association_config=config['association_config']
        )

        summary = response['Summary']
        print(f"\n✓ Web ACL created successfully!")
        print(f"  Name: {summary['Name']}")
        print(f"  ID: {summary['Id']}")
        print(f"  ARN: {summary['ARN']}")
        
    except (ValueError, TypeError) as e:
        print(f"\nError: Invalid parameters for Web ACL creation: {e}")
        sys.exit(1)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'WAFDuplicateItemException':
            print(f"\nError: A Web ACL with name '{args.name}' already exists.")
            print("Use a different name or delete the existing Web ACL first.")
        elif error_code == 'WAFLimitsExceededException':
            print(f"\nError: WAF limits exceeded. {error_message}")
        elif error_code == 'WAFInvalidParameterException':
            print(f"\nError: Invalid parameter. {error_message}")
        else:
            print(f"\nError: {error_code} - {error_message}")
        sys.exit(1)
    print(f"  ARN: {summary['ARN']}")


def do_update_rule_group(args):
    """Handle rule group update."""
    # Validate required parameters upfront
    validate_scope_required(args, 'update-rule-group')
    validate_required_params(args, 'update-rule-group', ['name', 'id', 'input'])
    validate_file_exists(args.input, '--input')
    
    if args.arn_map:
        validate_file_exists(args.arn_map, '--arn-map')
    
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)

    # Load rules from file
    print(f"Loading rules from: {args.input}")
    data = load_from_file(args.input)

    try:
        rules, visibility_config, custom_response_bodies, description = extract_rules_from_json(data)
    except (ValueError, TypeError) as e:
        print(f"Error: Invalid rule data in input file: {e}")
        sys.exit(1)

    if not rules:
        print("Error: No rules found in input file")
        sys.exit(1)

    if args.arn_map:
        arn_map = load_arn_map(args.arn_map)
        rules = remap_arns(rules, arn_map)

    if args.description:
        description = args.description

    # Load rules from file

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
    if required_capacity == 0:
        print("Warning: Could not calculate capacity for new rules. Proceeding with caution.")
    else:
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
    print("Update Rule Group:")
    print(f"  Name: {args.name}")
    print(f"  ID: {args.id}")
    print(f"  Scope: {args.scope}")
    print(f"  Current Rules: {len(current['RuleGroup'].get('Rules', []))}")
    print(f"  New Rules: {len(rules)}")
    print(f"  Description: {description or '(none)'}")
    print('='*60)

    if not confirm_action("Update this rule group?", args.yes):
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
        
    except (ValueError, TypeError) as e:
        print(f"\nError: Invalid parameters for rule group update: {e}")
        sys.exit(1)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'WAFOptimisticLockException':
            print(f"\nError: Rule group was modified by another process. Please try again.")
        else:
            print(f"\nError: {error_code} - {error_message}")
        sys.exit(1)


def do_update_web_acl(args):
    """Handle Web ACL update."""
    # Validate required parameters upfront
    validate_scope_required(args, 'update-web-acl')
    validate_required_params(args, 'update-web-acl', ['name', 'id', 'input'])
    validate_file_exists(args.input, '--input')
    
    if args.arn_map:
        validate_file_exists(args.arn_map, '--arn-map')
    
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)

    print(f"Loading Web ACL config from: {args.input}")
    data = load_from_file(args.input)

    try:
        config = extract_web_acl_config(data)
    except (ValueError, TypeError) as e:
        print(f"Error: Invalid Web ACL configuration in input file: {e}")
        sys.exit(1)
        
    rules = config['rules']

    if args.arn_map:
        arn_map = load_arn_map(args.arn_map)
        rules = remap_arns(rules, arn_map)

    if args.description:
        config['description'] = args.description

    waf_client = get_waf_client(args.scope, args.region)

    print(f"Fetching current Web ACL: {args.name}")
    current = get_web_acl(waf_client, args.name, args.scope, args.id)
    lock_token = current['LockToken']
    current_acl = current['WebACL']

    # Use current values for anything not in the import
    if config['default_action'] is None:
        default_action = current_acl.get('DefaultAction', {'Allow': {}})
    else:
        default_action = config['default_action']
    
    if args.default_action:
        default_action = {'Allow': {}} if args.default_action.lower() == 'allow' else {'Block': {}}

    if not config['visibility_config']:
        config['visibility_config'] = current_acl.get('VisibilityConfig')
    if not config['description']:
        config['description'] = current_acl.get('Description', '')

    print(f"\n{'=' * 60}")
    print(f"Update Web ACL:")
    print(f"  Name: {args.name}")
    print(f"  Current Rules: {len(current_acl.get('Rules', []))}")
    print(f"  New Rules: {len(rules)}")
    print(f"  Default Action: {json.dumps(default_action)}")
    print(f"{'=' * 60}")

    if not confirm_action("Update this Web ACL?", args.yes):
        print("Aborted.")
        return

    print("\nUpdating Web ACL...")
    try:
        response = update_web_acl(
            waf_client=waf_client,
            name=args.name,
            scope=args.scope,
            web_acl_id=args.id,
            rules=rules,
            default_action=default_action,
            lock_token=lock_token,
            description=config['description'],
            visibility_config=config['visibility_config'],
            custom_response_bodies=config['custom_response_bodies'],
            captcha_config=config['captcha_config'],
            challenge_config=config['challenge_config'],
            token_domains=config['token_domains'],
            association_config=config['association_config']
        )
        print(f"\n✓ Web ACL updated successfully!")
        print(f"  Next Lock Token: {response['NextLockToken']}")
        
    except (ValueError, TypeError) as e:
        print(f"\nError: Invalid parameters for Web ACL update: {e}")
        sys.exit(1)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        if error_code == 'WAFOptimisticLockException':
            print(f"\nError: Web ACL was modified by another process. Please try again.")
        elif error_code == 'WAFInvalidParameterException':
            print(f"\nError: Invalid parameter. {error_message}")
        else:
            print(f"\nError: {error_code} - {error_message}")
        sys.exit(1)


def do_clone_rule_group(args):
    """Handle rule group clone - export and create in one step."""
    # Validate required parameters upfront
    validate_scope_required(args, 'clone-rule-group')
    validate_required_params(args, 'clone-rule-group', ['new_name'])
    
    if args.arn_map:
        validate_file_exists(args.arn_map, '--arn-map')
    
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)

    waf_client = get_waf_client(args.scope, args.region)
    dest_client = waf_client

    # If destination region is different
    if args.dest_region and args.dest_region != args.region:
        dest_client = get_waf_client(args.scope, args.dest_region)

    # Validate: either (source_name + source_id) or interactive selection
    has_source = hasattr(args, 'source_name') and args.source_name and hasattr(args, 'source_id') and args.source_id

    # Get source rule group
    if has_source:
        source_name, source_id = args.source_name, args.source_id
    else:
        source_name, source_id = interactive_select_rule_group(waf_client, args.scope)
        if not source_name:
            return

    print(f"\nFetching source rule group: {source_name}")
    try:
        source = get_rule_group(waf_client, source_name, args.scope, source_id)
        source_rg = source['RuleGroup']
    except ClientError as e:
        print(f"Error: Could not find source rule group '{source_name}' with ID '{source_id}'")
        sys.exit(1)

    rules = source_rg.get('Rules', [])
    print(f"Found {len(rules)} rules")

    if args.arn_map:
        arn_map = load_arn_map(args.arn_map)
        rules = remap_arns(rules, arn_map)

    # Calculate capacity for destination
    if args.capacity:
        capacity = args.capacity
    else:
        capacity = source_rg.get('Capacity', 100)

    print(f"\n{'=' * 60}")
    print(f"Clone Rule Group:")
    print(f"  Source: {source_name} ({args.region})")
    print(f"  Destination: {args.new_name} ({args.dest_region or args.region})")
    print(f"  Capacity: {capacity}")
    print(f"  Rules: {len(rules)}")
    print('='*60)

    if not confirm_action("Clone?", args.yes):
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
        
        summary = response.get('Summary', {})
        print(f"\n✓ Rule group cloned successfully!")
        print(f"  Name: {summary.get('Name', 'N/A')}")
        print(f"  ID: {summary.get('Id', 'N/A')}")
        print(f"  ARN: {summary.get('ARN', 'N/A')}")
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        print(f"\nError: {error_code} - {error_message}")
        sys.exit(1)


def do_clone_web_acl(args):
    """Handle Web ACL clone."""
    # Validate required parameters upfront
    validate_scope_required(args, 'clone-web-acl')
    validate_required_params(args, 'clone-web-acl', ['new_name'])
    
    if args.arn_map:
        validate_file_exists(args.arn_map, '--arn-map')
    
    if args.profile:
        boto3.setup_default_session(profile_name=args.profile)

    waf_client = get_waf_client(args.scope, args.region)
    dest_client = waf_client
    if args.dest_region and args.dest_region != args.region:
        dest_client = get_waf_client(args.scope, args.dest_region)

    # Validate: either (source_name + source_id) or interactive selection
    has_source = hasattr(args, 'source_name') and args.source_name and hasattr(args, 'source_id') and args.source_id

    if has_source:
        source_name, source_id = args.source_name, args.source_id
    else:
        source_name, source_id = interactive_select_web_acl(waf_client, args.scope)
        if not source_name:
            return

    print(f"\nFetching source Web ACL: {source_name}")
    source = get_web_acl(waf_client, source_name, args.scope, source_id)
    source_acl = source['WebACL']
    rules = source_acl.get('Rules', [])

    if args.arn_map:
        arn_map = load_arn_map(args.arn_map)
        rules = remap_arns(rules, arn_map)

    default_action = source_acl.get('DefaultAction', {'Allow': {}})
    if args.default_action:
        default_action = {'Allow': {}} if args.default_action.lower() == 'allow' else {'Block': {}}

    rule_types = summarize_rules(rules)

    print(f"\n{'=' * 60}")
    print(f"Clone Web ACL:")
    print(f"  Source: {source_name} ({args.region})")
    print(f"  Dest: {args.new_name} ({args.dest_region or args.region})")
    print(f"  Default Action: {json.dumps(default_action)}")
    print(f"  Rules: {len(rules)}")
    for rule_type, count in rule_types.items():
        print(f"    {rule_type}: {count}")
    print(f"{'=' * 60}")

    if not confirm_action("Clone?", args.yes):
        print("Aborted.")
        return

    response = create_web_acl(
        waf_client=dest_client,
        name=args.new_name,
        scope=args.scope,
        rules=rules,
        default_action=default_action,
        description=args.description or source_acl.get('Description', f'Cloned from {source_name}'),
        visibility_config=source_acl.get('VisibilityConfig'),
        custom_response_bodies=source_acl.get('CustomResponseBodies'),
        captcha_config=source_acl.get('CaptchaConfig'),
        challenge_config=source_acl.get('ChallengeConfig'),
        token_domains=source_acl.get('TokenDomains'),
        association_config=source_acl.get('AssociationConfig')
    )

    summary = response['Summary']
    print(f"\n✓ Web ACL cloned!")
    print(f"  Name: {summary['Name']}")
    print(f"  ID: {summary['Id']}")
    print(f"  ARN: {summary['ARN']}")


def summarize_rules(rules: List[Dict]) -> Dict[str, int]:
    """Summarize rule types."""
    summary = {}
    for rule in rules:
        statement = rule.get('Statement', {})
        rule_type = 'Custom'

        if 'ManagedRuleGroupStatement' in statement:
            vendor = statement['ManagedRuleGroupStatement'].get('VendorName', 'Unknown')
            group_name = statement['ManagedRuleGroupStatement'].get('Name', 'Unknown')
            rule_type = f'ManagedRuleGroup ({vendor}/{group_name})'
        elif 'RuleGroupReferenceStatement' in statement:
            rule_type = 'RuleGroupReference'
        elif 'RateBasedStatement' in statement:
            rule_type = 'RateBased'
        elif 'IPSetReferenceStatement' in statement:
            rule_type = 'IPSet'
        elif 'RegexPatternSetReferenceStatement' in statement:
            rule_type = 'RegexPatternSet'
        elif 'ByteMatchStatement' in statement:
            rule_type = 'ByteMatch'
        elif 'GeoMatchStatement' in statement:
            rule_type = 'GeoMatch'
        elif 'SizeConstraintStatement' in statement:
            rule_type = 'SizeConstraint'
        elif 'SqliMatchStatement' in statement:
            rule_type = 'SQLInjection'
        elif 'XssMatchStatement' in statement:
            rule_type = 'XSS'
        elif 'LabelMatchStatement' in statement:
            rule_type = 'LabelMatch'
        elif 'AndStatement' in statement:
            rule_type = 'And (compound)'
        elif 'OrStatement' in statement:
            rule_type = 'Or (compound)'
        elif 'NotStatement' in statement:
            rule_type = 'Not (compound)'

        summary[rule_type] = summary.get(rule_type, 0) + 1

    return summary


# ============================================================
# Argument Parser Setup
# ============================================================

def add_common_args(parser):
    """Add common arguments to a parser."""
    parser.add_argument('--scope', choices=['REGIONAL', 'CLOUDFRONT'])
    parser.add_argument('--region', default='us-east-1')
    parser.add_argument('--profile', help='AWS profile name')


def add_create_args(parser):
    """Add common create arguments."""
    parser.add_argument('--tags', nargs='+', help='Tags: Key=Value')
    parser.add_argument('--yes', '-y', action='store_true', help='Skip confirmation')
    parser.add_argument('--arn-map', help='JSON file mapping old ARNs to new ARNs')


def main():
    parser = argparse.ArgumentParser(
        description='AWS WAF Rule Group & Web ACL Management Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  list                  List WAF resources
  export-rule-group     Export rule group rules
  export-web-acl        Export Web ACL rules
  export-all            Export all WAF resources
  create-rule-group     Create rule group from JSON
  create-web-acl        Create Web ACL from JSON
  update-rule-group     Update existing rule group
  update-web-acl        Update existing Web ACL
  clone-rule-group      Clone a rule group
  clone-web-acl         Clone a Web ACL
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # ========== LIST ==========
    p = subparsers.add_parser('list', help='List WAF resources')
    add_common_args(p)
    p.add_argument('--type', choices=['all', 'rule-groups', 'rg', 'web-acls', 'waf'],
                   default='all', help='Resource type to list')

    # ========== EXPORT RULE GROUP ==========
    p = subparsers.add_parser('export-rule-group', help='Export rule group')
    add_common_args(p)
    p.add_argument('--name', help='Rule group name')
    p.add_argument('--id', help='Rule group ID')
    p.add_argument('--arn', help='Rule group ARN')
    p.add_argument('--output', '-o', help='Output filename')
    p.add_argument('--full', action='store_true', help='Full export')

    # ========== EXPORT WEB ACL ==========
    p = subparsers.add_parser('export-web-acl', help='Export Web ACL')
    add_common_args(p)
    p.add_argument('--name', help='Web ACL name')
    p.add_argument('--id', help='Web ACL ID')
    p.add_argument('--output', '-o', help='Output filename')
    p.add_argument('--full', action='store_true', help='Full export')
    p.add_argument('--no-resources', action='store_true',
                   help='Skip exporting associated resources')

    # ========== EXPORT ALL ==========
    p = subparsers.add_parser('export-all', help='Export all WAF resources')
    add_common_args(p)
    p.add_argument('--output', '-o', help='Output filename')

    # ========== CREATE RULE GROUP ==========
    p = subparsers.add_parser('create-rule-group', help='Create rule group from JSON')
    add_common_args(p)
    p.add_argument('--name', required=True, help='New rule group name')
    p.add_argument('--input', '-i', required=True, help='Input JSON file')
    p.add_argument('--capacity', type=int, help='Capacity (auto-calculated if omitted)')
    p.add_argument('--capacity-buffer', type=int, default=0, help='%% buffer for capacity')
    p.add_argument('--description', help='Description')
    add_create_args(p)

    # ========== CREATE WEB ACL ==========
    p = subparsers.add_parser('create-web-acl', help='Create Web ACL from JSON')
    add_common_args(p)
    p.add_argument('--name', required=True, help='New Web ACL name')
    p.add_argument('--input', '-i', required=True, help='Input JSON file')
    p.add_argument('--default-action', choices=['allow', 'block'],
                   help='Default action (overrides JSON)')
    p.add_argument('--description', help='Description')
    add_create_args(p)

    # ========== UPDATE RULE GROUP ==========
    p = subparsers.add_parser('update-rule-group', help='Update existing rule group')
    add_common_args(p)
    p.add_argument('--name', required=True, help='Rule group name')
    p.add_argument('--id', required=True, help='Rule group ID')
    p.add_argument('--input', '-i', required=True, help='Input JSON file')
    p.add_argument('--description', help='New description')
    p.add_argument('--yes', '-y', action='store_true')
    p.add_argument('--arn-map', help='ARN mapping file')

    # ========== UPDATE WEB ACL ==========
    p = subparsers.add_parser('update-web-acl', help='Update existing Web ACL')
    add_common_args(p)
    p.add_argument('--name', required=True, help='Web ACL name')
    p.add_argument('--id', required=True, help='Web ACL ID')
    p.add_argument('--input', '-i', required=True, help='Input JSON file')
    p.add_argument('--default-action', choices=['allow', 'block'])
    p.add_argument('--description', help='New description')
    p.add_argument('--yes', '-y', action='store_true')
    p.add_argument('--arn-map', help='ARN mapping file')

    # ========== CLONE RULE GROUP ==========
    p = subparsers.add_parser('clone-rule-group', help='Clone a rule group')
    add_common_args(p)
    p.add_argument('--source-name', help='Source name')
    p.add_argument('--source-id', help='Source ID')
    p.add_argument('--new-name', required=True, help='New name')
    p.add_argument('--dest-region', help='Destination region')
    p.add_argument('--capacity', type=int, help='Override capacity')
    p.add_argument('--description', help='Description')
    add_create_args(p)

    # ========== CLONE WEB ACL ==========
    p = subparsers.add_parser('clone-web-acl', help='Clone a Web ACL')
    add_common_args(p)
    p.add_argument('--source-name', help='Source name')
    p.add_argument('--source-id', help='Source ID')
    p.add_argument('--new-name', required=True, help='New name')
    p.add_argument('--dest-region', help='Destination region')
    p.add_argument('--default-action', choices=['allow', 'block'])
    p.add_argument('--description', help='Description')
    add_create_args(p)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Validate command exists
    handlers = {
        'list': do_list,
        'export-rule-group': do_export_rule_group,
        'export-web-acl': do_export_web_acl,
        'export-all': do_export_all,
        'create-rule-group': do_create_rule_group,
        'create-web-acl': do_create_web_acl,
        'update-rule-group': do_update_rule_group,
        'update-web-acl': do_update_web_acl,
        'clone-rule-group': do_clone_rule_group,
        'clone-web-acl': do_clone_web_acl,
    }

    handler = handlers.get(args.command)
    if not handler:
        print(f"Error: Unknown command '{args.command}'")
        parser.print_help()
        sys.exit(1)

    # Execute command with error handling
    try:
        handler(args)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_msg = e.response['Error']['Message']
        print(f"\nAWS Error [{error_code}]: {error_msg}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()