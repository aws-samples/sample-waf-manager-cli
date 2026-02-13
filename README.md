# AWS WAF Rule Group Manager

Managing AWS WAF rule groups through the console or AWS CLI can be challenging and error-prone, especially when dealing with complex configurations or multi-region deployments. This tool provides a Python CLI tool for exporting, importing, cloning, and managing AWS WAFv2 rule groups and Web ACLs. It simplifies the process of backing up WAF configurations, migrating rules between regions and accounts, and managing rule groups as code.

## Recent Improvements (February 2026)

This tool has been significantly enhanced with comprehensive error handling and validation:

- **Input validation before AWS API calls**: All parameters and JSON files are validated before making AWS API calls, saving quota and providing faster feedback
- **Clear, actionable error messages**: Every error includes specific guidance on how to fix the issue
- **Comprehensive AWS error handling**: Specific handling for all common AWS WAFv2 error codes
- **Graceful degradation**: Batch operations continue even if some resources fail, with detailed error tracking
- **Enhanced extraction functions**: Validates all rule structures, visibility configs, and Web ACL configurations
- **Improved command handlers**: All create/update operations validate inputs and handle exceptions properly
- **Better interactive functions**: Enhanced user experience with attempt limiting and clear feedback
- **Robust export operations**: Validates response structures and handles missing data gracefully

See the [Error Handling](#error-handling) section for detailed information.

### The Problem

**Manual WAF Management is Difficult:**
- **No native export/import**: AWS WAF doesn't provide a simple way to export rule groups to files or import them back
- **Multi-region complexity**: Deploying identical rule groups across regions requires manual recreation or complex scripting
- **No version control**: Rule configurations can't easily be tracked in Git or other version control systems
- **Disaster recovery gaps**: Backing up and restoring WAF configurations is manual and time-consuming
- **Testing challenges**: Creating staging/testing environments with production-like WAF rules is cumbersome
- **Capacity planning**: Understanding and managing WAF capacity units (WCUs) requires manual calculation

### The Solution

This tool provides a streamlined workflow for WAF rule group and web ACL lifecycle management:
## Features

- **Export to JSON**: Save rule groups and Web ACLs as portable JSON files for backup and version control
- **Import from JSON**: Create new or update existing resources from JSON files with automatic capacity calculation
- **Clone operations**: Duplicate rule groups within or across regions with a single command
- **Infrastructure as Code**: Manage WAF configurations alongside your application code
- **Automated capacity management**: Automatically calculate required WCUs or add safety buffers
- **List operations**: Easily list all rule groups and Web ACLs in a scope
- **Support for both REGIONAL and CLOUDFRONT scopes**
- **ARN-based lookups** for quick exports
- **Comprehensive error handling**: Clear, actionable error messages with input validation before AWS API calls
- **Batch operations**: Export all resources with error tracking and progress reporting
- **Interactive mode**: Select resources from a list when identifiers aren't provided
- **ARN remapping**: Remap ARNs when moving between accounts or regions
- **Tag support**: Add tags during resource creation
- **Flexible JSON formats**: Support for multiple JSON input formats

## Prerequisites

- Python 3.11+
- AWS credentials configured (via AWS CLI, environment variables, or IAM role)
- Appropriate IAM permissions for WAFv2 operations

### Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "wafv2:ListRuleGroups",
        "wafv2:GetRuleGroup",
        "wafv2:CreateRuleGroup",
        "wafv2:UpdateRuleGroup",
        "wafv2:CheckCapacity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Installation

1. Clone this repository or download the script:
```bash
git clone <repository-url>
cd waf_manager
```

2. Install required dependencies:
```bash
pip install boto3
```

3. Make the script executable (optional):
```bash
chmod +x waf_manager.py
```

## Getting Help

The tool has comprehensive built-in help for all commands and options:

```bash
# General help - shows all available commands
python waf_manager.py --help
python waf_manager.py -h

# Command-specific help with detailed examples
python waf_manager.py export --help
python waf_manager.py create --help
python waf_manager.py update --help
python waf_manager.py clone --help
python waf_manager.py list --help
```

### Quick Command Reference

| Command | Purpose | Required Flags |
|---------|---------|----------------|
| `list` | List all rule groups or Web ACLs | `--scope` |
| `export` | Export rule group or Web ACL to JSON | `--scope`, `--region` (or `--arn`) |
| `create-rule-group` | Create new rule group from JSON | `--scope`, `--name`, `--input` |
| `update-rule-group` | Update existing rule group | `--scope`, `--name`, `--id`, `--input` |
| `clone-rule-group` | Clone rule group | `--scope`, `--new-name` |
| `create-web-acl` | Create new Web ACL from JSON | `--scope`, `--name`, `--input` |
| `update-web-acl` | Update existing Web ACL | `--scope`, `--name`, `--id`, `--input` |
| `clone-web-acl` | Clone Web ACL | `--scope`, `--new-name` |
| `export-all` | Export all resources to JSON | `--scope`, `--output` |

### Common Flags

- `--scope`: `REGIONAL` (ALB/API Gateway) or `CLOUDFRONT` (CloudFront distributions)
- `--region`: AWS region (default: `us-east-1`, always `us-east-1` for CloudFront)
- `--profile`: AWS profile name from `~/.aws/credentials`
- `--yes` / `-y`: Skip confirmation prompts (useful for automation)
- `--output` / `-o`: Specify output filename
- `--input` / `-i`: Specify input JSON file

## Use Cases

### 1. Disaster Recovery & Business Continuity
**Scenario**: Your production WAF rule group is accidentally deleted or corrupted.

**Solution**:
```bash
# Regular backups
python waf_manager.py export --scope REGIONAL --region us-east-1 \
    --name ProductionRules --id abc123 --full --output backups/prod-rules-2026-02-05.json

# Quick restore when needed
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name ProductionRules --input backups/prod-rules-2026-02-05.json
```

### 2. Multi-Region Deployment
**Scenario**: You need identical WAF protection across multiple AWS regions for global applications.

**Solution**:
```bash
# Export from primary region
python waf_manager.py export --scope REGIONAL --region us-east-1 \
    --name GlobalProtection --id abc123 --output global-rules.json

# Deploy to all regions
for region in us-east-1 eu-west-1 ap-southeast-1; do
    python waf_manager.py create --scope REGIONAL --region $region \
        --name GlobalProtection --input global-rules.json --yes
done
```

### 3. Environment Promotion (Dev → Staging → Production)
**Scenario**: Test WAF rules in development before promoting to production.

**Solution**:
```bash
# Export from dev
python waf_manager.py export --scope REGIONAL --region us-east-1 \
    --name DevRules --id abc123 --output dev-rules.json

# Create in staging for testing
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name StagingRules --input dev-rules.json

# After validation, promote to production
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name ProductionRules --input dev-rules.json \
    --tags Environment=production Compliance=required
```

### 4. Version Control & Change Management
**Scenario**: Track WAF rule changes over time and enable rollback capabilities.

**Solution**:
```bash
# Export current configuration
python waf_manager.py export --scope REGIONAL --region us-east-1 \
    --name AppFirewall --id abc123 --full --output waf-configs/app-firewall.json

# Commit to Git
git add waf-configs/app-firewall.json
git commit -m "WAF: Add rate limiting rules for API endpoints"
git push

# Rollback if needed
git checkout HEAD~1 waf-configs/app-firewall.json
python waf_manager.py update --scope REGIONAL --region us-east-1 \
    --name AppFirewall --id abc123 --input waf-configs/app-firewall.json
```

### 5. CloudFront to Regional Migration
**Scenario**: Migrate from CloudFront WAF to Regional WAF (or vice versa).

**Solution**:
```bash
# Export from CloudFront
python waf_manager.py export --scope CLOUDFRONT \
    --name CloudFrontRules --id abc123 --output cf-rules.json

# Create as Regional WAF
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name RegionalRules --input cf-rules.json
```

### 6. Compliance & Audit Requirements
**Scenario**: Maintain documented evidence of WAF configurations for compliance audits.

**Solution**:
```bash
# Export all rule groups with full metadata
python waf_manager.py list --scope REGIONAL --region us-east-1 > audit/rule-groups-list.txt

# Export each with full configuration
python waf_manager.py export --scope REGIONAL --region us-east-1 \
    --name ComplianceRules --id abc123 --full --output audit/compliance-rules-Q1-2026.json

# Store in compliance documentation repository
```

### 7. Automated CI/CD Integration
**Scenario**: Deploy WAF rules as part of your infrastructure deployment pipeline.

**Solution**:
```yaml
# .github/workflows/deploy-waf.yml
- name: Deploy WAF Rules
  run: |
    python waf_manager.py create --scope REGIONAL --region ${{ env.AWS_REGION }} \
        --name ${{ env.APP_NAME }}-waf \
        --input infrastructure/waf-rules.json \
        --tags Application=${{ env.APP_NAME }} Environment=${{ env.ENVIRONMENT }} \
        --yes
```

### 8. Capacity Planning & Optimization
**Scenario**: Understand WAF capacity requirements before deployment.

**Solution**:
```bash
# Check capacity with automatic calculation
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name TestRules --input new-rules.json --capacity-buffer 20

# Output shows: "Calculated capacity: 450" and "Adding 20% buffer: 450 -> 540"
```

### 9. Rule Development & Testing
**Scenario**: Develop and test new WAF rules without affecting production.

**Solution**:
```bash
# Clone production to sandbox
python waf_manager.py clone --scope REGIONAL --region us-east-1 \
    --source-name ProductionRules --source-id abc123 \
    --new-name SandboxRules

# Modify rules locally (edit JSON file)
# Test in sandbox environment
# Export tested rules
python waf_manager.py export --scope REGIONAL --region us-east-1 \
    --name SandboxRules --id xyz789 --output tested-rules.json

# Update production after validation
python waf_manager.py update --scope REGIONAL --region us-east-1 \
    --name ProductionRules --id abc123 --input tested-rules.json
```

## Usage

### Export Commands

#### Interactive Export
Select a rule group from a list:
```bash
python waf_manager.py export --scope REGIONAL --region us-east-1
```

#### Export by Name and ID
```bash
python waf_manager.py export --scope REGIONAL --region us-east-1 \
    --name MyRuleGroup --id abc123def456
```

#### Export by ARN
```bash
python waf_manager.py export \
    --arn arn:aws:wafv2:us-east-1:123456789012:regional/rulegroup/MyRuleGroup/abc123
```

#### Export Full Configuration
Includes metadata, visibility config, and custom response bodies:
```bash
python waf_manager.py export --scope REGIONAL --region us-east-1 \
    --name MyRuleGroup --id abc123 --full --output backup.json
```

#### List All Rule Groups 
```bash
python waf_manager.py list --scope REGIONAL --region us-east-1
```

### Create Commands

#### Create from Exported JSON 
```bash
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name NewRuleGroup --input exported-rules.json
```

#### Create with Specific Capacity 
```bash
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name NewRuleGroup --input rules.json --capacity 500
```

#### Create with Capacity Buffer 
Adds a percentage buffer to auto-calculated capacity:
```bash
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name NewRuleGroup --input rules.json --capacity-buffer 20
```

#### Create with Tags 
```bash
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name NewRuleGroup --input rules.json \
    --tags Environment=production Team=security Owner=alice.jones
```

#### Create for CloudFront 
```bash
python waf_manager.py create --scope CLOUDFRONT \
    --name CloudFrontRuleGroup --input rules.json
```

### Update Commands

#### Update Existing Rule Group 
```bash
python waf_manager.py update-rule-group --scope REGIONAL --region us-east-1 \
    --name MyRuleGroup --id abc123def456 --input new-rules.json
```

#### Update with New Description 
```bash
python waf_manager.py update-rule-group --scope REGIONAL --region us-east-1 \
    --name MyRuleGroup --id abc123 --input rules.json \
    --description "Updated rules for Q1 2026"
```

### Web ACL Commands

#### Create Web ACL
```bash
python waf_manager.py create-web-acl --scope REGIONAL --region us-east-1 \
    --name MyWebACL --input web-acl-config.json
```

#### Create Web ACL with Default Action
```bash
python waf_manager.py create-web-acl --scope REGIONAL --region us-east-1 \
    --name MyWebACL --input web-acl-config.json --default-action block
```

#### Update Web ACL
```bash
python waf_manager.py update-web-acl --scope REGIONAL --region us-east-1 \
    --name MyWebACL --id xyz789 --input new-web-acl-config.json
```

#### Clone Web ACL
```bash
python waf_manager.py clone-web-acl --scope REGIONAL --region us-east-1 \
    --source-name ProductionWebACL --source-id abc123 \
    --new-name StagingWebACL
```

#### Export All Resources
Export all rule groups and Web ACLs in one operation:
```bash
python waf_manager.py export-all --scope REGIONAL --region us-east-1 \
    --output all-waf-resources.json
```

### Clone Commands

#### Clone to Same Region 
```bash
python waf_manager.py clone --scope REGIONAL --region us-east-1 \
    --source-name ProductionRules --source-id abc123 \
    --new-name StagingRules
```

#### Clone to Different Region (DR/Multi-Region) 
```bash
python waf_manager.py clone --scope REGIONAL --region us-east-1 \
    --source-name MyRuleGroup --source-id abc123 \
    --new-name MyRuleGroup-DR --dest-region eu-west-1
```

#### Interactive Clone 
```bash
python waf_manager.py clone --scope REGIONAL --region us-east-1 \
    --new-name ClonedRuleGroup
```

### AWS Profile Support

Use a specific AWS profile (example):
```bash
python waf_manager.py export --scope REGIONAL --region us-east-1 \
    --profile production --name MyRuleGroup --id abc123
```

### Skip Confirmation Prompts

Use `-y` or `--yes` for automation (example):
```bash
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name AutomatedRuleGroup --input rules.json --yes
```

## JSON File Formats

The tool supports multiple JSON formats for flexibility:

### Rule Group Formats

#### Format 1: Rules Only (WAF Console JSON Editor Format)
```json
{
  "Rules": [
    {
      "Name": "BlockBadIPs",
      "Priority": 0,
      "Statement": {
        "IPSetReferenceStatement": {
          "Arn": "arn:aws:wafv2:us-east-1:123456789012:regional/ipset/BadIPs/abc123"
        }
      },
      "Action": {
        "Block": {}
      },
      "VisibilityConfig": {
        "SampledRequestsEnabled": true,
        "CloudWatchMetricsEnabled": true,
        "MetricName": "BlockBadIPs"
      }
    }
  ]
}
```

#### Format 2: Full Export (Complete Configuration)
```json
{
  "RuleGroup": {
    "Name": "MyRuleGroup",
    "Id": "abc123def456",
    "ARN": "arn:aws:wafv2:us-east-1:123456789012:regional/rulegroup/MyRuleGroup/abc123",
    "Capacity": 100,
    "Description": "Production rule group",
    "Rules": [...],
    "VisibilityConfig": {...},
    "CustomResponseBodies": {...}
  },
  "LockToken": "..."
}
```

#### Format 3: Direct Array
```json
[
  {
    "Name": "Rule1",
    "Priority": 0,
    ...
  }
]
```

### Web ACL Formats

#### Web ACL Configuration
```json
{
  "WebACL": {
    "Name": "MyWebACL",
    "Id": "xyz789",
    "DefaultAction": {
      "Allow": {}
    },
    "Rules": [
      {
        "Name": "RateLimitRule",
        "Priority": 0,
        "Statement": {
          "RateBasedStatement": {
            "Limit": 2000,
            "AggregateKeyType": "IP"
          }
        },
        "Action": {
          "Block": {}
        },
        "VisibilityConfig": {
          "SampledRequestsEnabled": true,
          "CloudWatchMetricsEnabled": true,
          "MetricName": "RateLimitRule"
        }
      }
    ],
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "MyWebACL"
    },
    "CaptchaConfig": {
      "ImmunityTimeProperty": {
        "ImmunityTime": 300
      }
    }
  }
}
```

### Required Fields

#### Rule Requirements
- `Name`: String (1-128 characters)
- `Priority`: Integer (unique within rule group/Web ACL)
- `Statement`: Object (rule logic)
- `Action`: Object (`Allow`, `Block`, `Count`, `Captcha`, or `Challenge`)
- `VisibilityConfig`: Object (metrics configuration)

#### Web ACL Requirements
- `DefaultAction`: Object (`Allow` or `Block`)
- `Rules`: Array (can be empty)
- `VisibilityConfig`: Object (metrics configuration)

## Common Workflows

### Backup and Restore
```bash
# Backup
python waf_manager.py export --scope REGIONAL --region us-east-1 \
    --name ProductionRules --id abc123 --full --output backup.json

# Restore (if deleted)
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name ProductionRules --input backup.json
```

### Multi-Region Deployment
```bash
# Export from primary region
python waf_manager.py export --scope REGIONAL --region us-east-1 \
    --name MyRules --id abc123 --output rules.json

# Deploy to secondary regions
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name MyRules --input rules.json

python waf_manager.py create --scope REGIONAL --region eu-west-1 \
    --name MyRules --input rules.json
```

### Rule Development Workflow
```bash
# Export production rules
python waf_manager.py export --scope REGIONAL --region us-east-1 \
    --name ProdRules --id abc123 --output prod-rules.json

# Edit rules locally (modify prod-rules.json)

# Test in staging
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name StagingRules --input prod-rules.json

# After testing, update production
python waf_manager.py update --scope REGIONAL --region us-east-1 \
    --name ProdRules --id abc123 --input prod-rules.json
```

### Version Control Integration
```bash
# Export all rule groups for backup
python waf_manager.py list --scope REGIONAL --region us-east-1 > rule-groups.txt

# Export each to JSON and commit to git
python waf_manager.py export --scope REGIONAL --region us-east-1 \
    --name RuleGroup1 --id abc123 --full --output rulegroup1.json

git add rulegroup1.json
git commit -m "Backup WAF rule group configuration"
git push
```

## Capacity Management

WAF rule groups have a capacity limit (default max: 1500 WCUs). The tool handles capacity automatically:

- **Auto-calculation**: Uses `CheckCapacity` API to determine required capacity
- **Manual override**: Specify `--capacity` if auto-calculation fails
- **Buffer**: Add `--capacity-buffer 20` for 20% extra capacity
- **Update validation**: Prevents updates that exceed existing capacity
- **Capacity range validation**: Ensures capacity is between 1 and 1500 WCUs
- **Clear error messages**: Shows required vs. available capacity when limits are exceeded

### Capacity Best Practices

1. **Use capacity buffers for production**: Add 10-20% buffer for future rule additions
   ```bash
   python waf_manager.py create --scope REGIONAL --region us-east-1 \
       --name ProductionRules --input rules.json --capacity-buffer 20
   ```

2. **Monitor capacity usage**: Export rules regularly to track capacity consumption

3. **Plan for growth**: If approaching capacity limits, consider splitting into multiple rule groups

4. **Cannot increase capacity**: Remember that AWS doesn't allow increasing capacity of existing rule groups - plan ahead

## Best Practices

### Input Validation
- **Validate JSON before import**: Use a JSON validator to check syntax
- **Test with small rule sets**: Start with minimal rules to verify configuration
- **Use full exports for backups**: Include all metadata with `--full` flag
- **Version control your configs**: Store JSON files in Git for change tracking

### Error Handling
- **Check error messages carefully**: The tool provides specific guidance for each error type
- **Validate inputs locally**: Check file paths and JSON structure before running commands
- **Use --yes flag in automation**: Skip confirmation prompts in CI/CD pipelines
- **Handle lock token expiration**: Re-export if updates fail with optimistic lock errors

### Multi-Region Deployments
- **Export once, deploy many**: Export from one region and deploy to all others
- **Use ARN remapping**: Remap ARNs when moving between accounts/regions
- **Test in non-production first**: Validate configurations in dev/staging before production
- **Maintain region-specific configs**: Some rules may need regional customization

### Backup and Recovery
- **Regular backups**: Export configurations on a schedule (daily/weekly)
- **Full exports for DR**: Use `--full` flag to capture all metadata
- **Test restore procedures**: Periodically test creating from backups
- **Store backups securely**: Keep JSON files in secure, version-controlled storage

### CI/CD Integration
- **Use --yes flag**: Skip interactive prompts in automated pipelines
- **Validate before deploy**: Check JSON structure in CI before deployment
- **Tag resources**: Use `--tags` to track deployments and ownership
- **Handle failures gracefully**: Check exit codes and handle errors in scripts

## Error Handling

The tool has been enhanced with comprehensive error handling throughout all operations, providing clear, actionable error messages for common issues:

### Input Validation Errors
- **Missing required parameters**: Validates all required parameters upfront before making AWS API calls
- **Invalid file paths**: Checks that input files exist before attempting to read them
- **Invalid JSON structure**: Validates JSON structure and provides specific parsing errors
- **Missing required fields**: Validates that all required fields are present in JSON files
- **Invalid data types**: Checks that fields have the correct data types (strings, numbers, lists, etc.)
- **Malformed configurations**: Validates rule structure, visibility config, and other WAF-specific requirements

### AWS API Errors
- **Duplicate names**: Suggests using a different name or deleting the existing resource
- **Capacity exceeded**: Shows required vs. available capacity with actionable guidance
- **Optimistic lock failures**: Suggests retrying the operation when resources are modified concurrently
- **Permission errors**: Indicates missing IAM permissions with specific error codes
- **Throttling errors**: Handles rate limiting with appropriate error messages
- **Invalid parameters**: Provides detailed AWS error messages for invalid configurations
- **Resource not found**: Clear messages when resources don't exist

### Operation-Specific Errors
- **Export operations**: Validates response structure and handles missing data gracefully
- **Create operations**: Validates all parameters before creation, including name length, capacity range, and rule structure
- **Update operations**: Validates lock tokens and prevents capacity increases
- **Clone operations**: Handles cross-region cloning errors and ARN remapping issues
- **List operations**: Handles pagination errors and empty result sets

### Error Recovery Features
- **Graceful degradation**: Export operations continue even if some resources fail
- **Error tracking**: Batch operations track which resources succeeded and which failed
- **Keyboard interrupt handling**: Clean exit when user cancels long-running operations
- **Progress tracking**: Shows progress before cancellation in batch operations
- **Detailed error context**: Provides file names, line numbers, and specific field names in error messages

### Validation Before AWS API Calls
The tool validates all inputs before making AWS API calls, which:
- Saves AWS API quota
- Provides faster feedback to users
- Reduces unnecessary AWS charges
- Prevents partial failures in batch operations

### Example Error Messages

**Missing Required Parameter:**
```
Error: Missing required parameter for create-rule-group: --name
Required parameters: name, input
```

**Invalid JSON Structure:**
```
Error: Invalid rule data in input file: Rules must be a list, got: dict
```

**Invalid Rule Configuration:**
```
Error: Invalid parameters for rule group creation: Rule at index 2 missing required field 'Name'
```

**Capacity Validation:**
```
Error: Capacity must be between 1 and 1500, got: 2000
```

**AWS API Error:**
```
Error: A rule group with name 'ProductionRules' already exists.
Use a different name or delete the existing rule group first.
```

## Troubleshooting

### Common Issues and Solutions

#### "Could not calculate capacity"
**Cause**: The AWS CheckCapacity API failed or returned an error.

**Solution**: Manually specify capacity:
```bash
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name MyRuleGroup --input rules.json --capacity 500
```

#### "Rule group already exists"
**Cause**: A rule group with the same name already exists in the specified scope.

**Solution**: Use a different name or delete the existing rule group first:
```bash
# Use a different name
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name MyRuleGroup-v2 --input rules.json

# Or delete the existing one first (via AWS Console or CLI)
```

#### "WAFOptimisticLockException"
**Cause**: Another process modified the rule group between when you fetched it and when you tried to update it.

**Solution**: Retry the operation to get a fresh lock token:
```bash
python waf_manager.py update --scope REGIONAL --region us-east-1 \
    --name MyRuleGroup --id abc123 --input rules.json
```

#### "Invalid rule data in input file"
**Cause**: The JSON file has invalid structure or missing required fields.

**Solution**: Check the error message for specific details:
- Ensure Rules is a list, not a dict
- Verify each rule has Name, Priority, Statement, Action, and VisibilityConfig
- Check that all ARNs are valid and properly formatted
- Validate JSON syntax using a JSON validator

#### "Missing required parameter"
**Cause**: A required command-line parameter was not provided.

**Solution**: Check the error message and provide the missing parameter:
```bash
# Error shows: Missing required parameter for create-rule-group: --name
# Solution: Add the --name parameter
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name MyRuleGroup --input rules.json
```

#### "File not found"
**Cause**: The specified input file doesn't exist.

**Solution**: Check the file path and ensure the file exists:
```bash
# Check if file exists
ls -la rules.json

# Use absolute path if needed
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name MyRuleGroup --input /full/path/to/rules.json
```

#### "Capacity must be between 1 and 1500"
**Cause**: The specified or calculated capacity is outside the valid range.

**Solution**: Reduce the number of rules or complexity, or split into multiple rule groups:
```bash
# Check current capacity requirement
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name MyRuleGroup --input rules.json
# (Will show calculated capacity before failing)

# Split rules into multiple files if needed
```

#### "Cannot increase capacity of existing rule group"
**Cause**: AWS doesn't allow increasing the capacity of an existing rule group.

**Solution**: Create a new rule group with higher capacity:
```bash
# Export current rules
python waf_manager.py export --scope REGIONAL --region us-east-1 \
    --name OldRuleGroup --id abc123 --output rules.json

# Create new rule group with higher capacity
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name NewRuleGroup --input rules.json --capacity 1000

# Update your Web ACL to use the new rule group
# Delete the old rule group when ready
```

#### CloudFront Rule Groups
**Note**: CloudFront rule groups must use `--scope CLOUDFRONT` and are always in `us-east-1`:

```bash
python waf_manager.py export --scope CLOUDFRONT --name MyCloudFrontRules --id abc123
```

#### Permission Errors
**Cause**: Missing IAM permissions for WAFv2 operations.

**Solution**: Ensure your IAM user/role has the required permissions (see Prerequisites section).

#### Throttling Errors
**Cause**: Too many API requests in a short time period.

**Solution**: Wait a moment and retry, or use `--yes` flag to reduce interactive prompts:
```bash
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name MyRuleGroup --input rules.json --yes
```

### Debug Tips

1. **Check AWS credentials**: Ensure your AWS credentials are configured correctly
   ```bash
   aws sts get-caller-identity
   ```

2. **Verify region**: Ensure you're using the correct region
   ```bash
   aws wafv2 list-rule-groups --scope REGIONAL --region us-east-1
   ```

3. **Validate JSON**: Use a JSON validator to check your input files
   ```bash
   python -m json.tool rules.json
   ```

4. **Check CloudTrail**: Review CloudTrail logs for detailed API error information

5. **Test with simple rules**: Start with a minimal rule set to isolate issues

## Limitations

- Cannot increase capacity of existing rule groups (AWS limitation)
- Rule group names must be unique within a scope
- Web ACL names must be unique within a scope
- Some rule types may require additional AWS resources (IP sets, regex pattern sets, managed rule groups)
- Lock tokens expire after a period of inactivity, requiring fresh exports for updates
- Maximum capacity per rule group: 1500 WCUs (AWS limit)
- Cross-account operations require appropriate IAM permissions and trust relationships

## Known Issues and Workarounds

### Capacity Cannot Be Increased
**Issue**: AWS doesn't allow increasing the capacity of an existing rule group.

**Workaround**: Create a new rule group with higher capacity and migrate your Web ACLs to use it.

### Lock Token Expiration
**Issue**: Lock tokens expire if too much time passes between export and update.

**Workaround**: Re-export the resource immediately before updating.

### ARN References
**Issue**: Exported rules may contain ARNs that don't exist in the target account/region.

**Workaround**: Use the `--arn-map` parameter to remap ARNs during import (feature available in the tool).

## Author

Alex Waddell (AWS)  
Date: February 4, 2026

## Support

For issues or questions:
- Check AWS WAFv2 documentation: https://docs.aws.amazon.com/waf/
- Review IAM permissions
- Enable debug logging with `--profile` and check CloudTrail logs


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

