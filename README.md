AWS Inspector
============================
This composite collectes AWS Inspector CIS endpoint violations and reports on them


## Description
This composite collects AWS Inspector CIS endpoint violations and reports on them


## Hierarchy
![composite inheritance hierarchy](https://raw.githubusercontent.com/CloudCoreo/audit-aws-inspector/master/images/hierarchy.png "composite inheritance hierarchy")



## Required variables with no default

**None**


## Required variables with default

### `AUDIT_AWS_INSPECTOR_ALLOW_EMPTY`:
  * description: Would you like to receive empty reports? Options - true / false. Default is false.
  * default: false

### `AUDIT_AWS_INSPECTOR_SEND_ON`:
  * description: Send reports always or only when there is a change? Options - always / change. Default is change.
  * default: change

### `AUDIT_AWS_INSPECTOR_REGIONS`:
  * description: List of AWS regions to check. Default is all regions. Choices are us-east-1,us-east-2,us-west-1,us-west-2,ca-central-1,ap-south-1,ap-northeast-2,ap-southeast-1,ap-southeast-2,ap-northeast-1,eu-central-1,eu-west-1,eu-west-1,sa-east-1
  * default: us-east-1, us-east-2, us-west-1, us-west-2, ca-central-1, ap-south-1, ap-northeast-2, ap-southeast-1, ap-southeast-2, ap-northeast-1, eu-central-1, eu-west-1, eu-west-2, sa-east-1


## Optional variables with default

### `AUDIT_AWS_INSPECTOR_ALERT_LIST`:
  * description: Which alerts would you like to check for? Default is all ec2 ris alerts. Possible value is ec2-get-all-instances-older-than
  * default: inspector-findings

### `AUDIT_AWS_INSPECTOR_OWNER_TAG`:
  * description: Enter an AWS tag whose value is an email address of the owner of the EC2 object. (Optional)
  * default: NOT_A_TAG


## Optional variables with no default

### `AUDIT_AWS_INSPECTOR_RECIPIENT`:
  * description: Enter the email address(es) that will receive notifications. If more than one, separate each with a comma.

### `FILTERED_OBJECTS`:
  * description: JSON object of string or regex of aws objects to include or exclude and tag in audit

## Tags
1. AWS Inspector


## Categories
1. AWS Operations Automation



## Diagram
![diagram](https://raw.githubusercontent.com/CloudCoreo/audit-aws-ec2-ris/master/images/diagram.png "diagram")


## Icon
![icon](https://raw.githubusercontent.com/CloudCoreo/audit-aws-inspector/master/images/icon.png "icon")


