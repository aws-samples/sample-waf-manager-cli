# AWS WAF Rule Group Manager

Managing AWS WAF rule groups through the console or AWS CLI can be challenging and error-prone, especially when dealing with complex configurations or multi-region deployments. This tool provides a Python CLI tool for exporting, importing, cloning, and managing AWS WAFv2 rule groups. It therefore simplifies the process of backing up WAF configurations, migrating rules between regions and accounts, and managing rule groups as code.

### The Problem

**Manual WAF Management is Difficult:**
- **No native export/import**: AWS WAF doesn't provide a simple way to export rule groups to files or import them back
- **Multi-region complexity**: Deploying identical rule groups across regions requires manual recreation or complex scripting
- **No version control**: Rule configurations can't easily be tracked in Git or other version control systems
- **Disaster recovery gaps**: Backing up and restoring WAF configurations is manual and time-consuming
- **Testing challenges**: Creating staging/testing environments with production-like WAF rules is cumbersome
- **Capacity planning**: Understanding and managing WAF capacity units (WCUs) requires manual calculation

### The Solution

This tool provides a streamlined workflow for WAF rule group lifecycle management:
- **Export to JSON**: Save rule groups as portable JSON files for backup and version control
- **Import from JSON**: Create new or update existing rule groups from JSON files with automatic capacity calculation
- **Clone operations**: Duplicate rule groups within or across regions with a single command
- **Infrastructure as Code**: Manage WAF configurations alongside your application code
- **Automated capacity management**: Automatically calculate required WCUs or add safety buffers
- **List operations**: Easily list all rule groups in a scope
- **Support for both REGIONAL and CLOUDFRONT scopes**
- **ARN-based lookups** for quick exports


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
| `export` | Export rule group to JSON | `--scope`, `--region` (or `--arn`) |
| `create` | Create new rule group from JSON | `--scope`, `--name`, `--input` |
| `update` | Update existing rule group | `--scope`, `--name`, `--id`, `--input` |
| `clone` | Clone rule group | `--scope`, `--new-name` |
| `list` | List all rule groups | `--scope` |

### Common Flags

- `--scope`: `REGIONAL` (ALB/API Gateway) or `CLOUDFRONT` (CloudFront distributions)
- `--region`: AWS region (default: `us-east-1`, always `us-east-1` for CloudFront)
- `--profile`: AWS profile name from `~/.aws/credentials`
- `--yes` / `-y`: Skip confirmation prompts (useful for automation)
- `--output` / `-o`: Specify output filename
- `--input` / `-i`: Specify input JSON file

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
python waf_manager.py update --scope REGIONAL --region us-east-1 \
    --name MyRuleGroup --id abc123def456 --input new-rules.json
```

#### Update with New Description 
```bash
python waf_manager.py update --scope REGIONAL --region us-east-1 \
    --name MyRuleGroup --id abc123 --input rules.json \
    --description "Updated rules for Q1 2026"
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

### Format 1: Rules Only (WAF Console JSON Editor Format)
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

### Format 2: Full Export (Complete Configuration)
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

### Format 3: Direct Array
```json
[
  {
    "Name": "Rule1",
    "Priority": 0,
    ...
  }
]
```

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

## Error Handling

The tool provides clear error messages for common issues:

- **Duplicate names**: Suggests using a different name
- **Capacity exceeded**: Shows required vs. available capacity
- **Invalid JSON**: Points to the specific parsing error
- **Optimistic lock failures**: Suggests retrying the operation
- **Permission errors**: Indicates missing IAM permissions

## Troubleshooting

### "Could not calculate capacity"
Manually specify capacity:
```bash
python waf_manager.py create --scope REGIONAL --region us-east-1 \
    --name MyRuleGroup --input rules.json --capacity 500
```

### "Rule group already exists"
Use a different name or delete the existing rule group first.

### "WAFOptimisticLockException"
Another process modified the rule group. Retry the operation.

### CloudFront Rule Groups
Always use `--scope CLOUDFRONT` and region defaults to `us-east-1`:
```bash
python waf_manager.py export --scope CLOUDFRONT --name MyCloudFrontRules --id abc123
```

## Limitations

- Cannot increase capacity of existing rule groups (AWS limitation)
- Rule group names must be unique within a scope
- Some rule types may require additional AWS resources (IP sets, regex pattern sets)
- Lock tokens expire, requiring fresh exports for updates

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

