coreo_aws_rule "inspector-findings" do
  action :define
  service :inspector
  display_name "Check Inspector Findings"
  description "This rule is an inventory of vulnerabilities across AWS Inspector reports"
  category "Endpoints"
  suggested_action "N/A"
  level "Inventory"
  objectives ["list_findings", "describe_findings"]
  call_modifiers [ {}, {finding_arns: ["finding_arns"]} ]
  audit_objects ["", "object.findings.arn"]
  operators ["", "=~"]
  raise_when ["", //]
  id_map "object.findings.arn"
end

coreo_uni_util_variables "inspector-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.inspector-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.inspector-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.inspector-planwide.results' => 'unset'},
                {'GLOBAL::number_violations' => '0'}
            ])
end

coreo_aws_rule_runner "advise-inspector" do
  action :run
  service :inspector
  rules ${AUDIT_AWS_INSPECTOR_ALERT_LIST}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_uni_util_jsrunner "usage" do
  action :run
  json_input 'COMPOSITE::coreo_aws_rule_runner.advise-inspector.report'
  function <<-EOH
    var new_report = {};

    for (region in json_input) {
        for (inspector_rule_arn in json_input[region]) {

            var violations = json_input[region][inspector_rule_arn]['violations'];
            var violator_info = json_input[region][inspector_rule_arn]['violator_info'];
            var tags = json_input[region][inspector_rule_arn]['tags'];
            var violator_id = violator_info['asset_attributes']['agent_id'];

            var ruleid = violator_info['id'];
            var service = violator_info['service'];
            var display_name = violator_info['attributes'].find(o => o.key === 'BENCHMARK_RULE_ID')['value'];
            var description = violator_info['description'];
            var suggested_action = violator_info['recommendation'];
            var level = violator_info['severity'];

            var meta_cis_id = display_name.split(' ')[0];
            var meta_cis_level = violator_info['attributes'].find(o => o.key === 'CIS_BENCHMARK_PROFILE')['value'];

            for (cc_rule_name in violations) {

                var result_info = violations[cc_rule_name]['result_info'];
                var category = violations[cc_rule_name]['category'];
                var include_violations_in_count = violations[cc_rule_name]['include_violations_in_count'];

                if (!new_report[region]) { new_report[region] = {} };
                if (!new_report[region][violator_id]) { new_report[region][violator_id] = {} };
                if (!new_report[region][violator_id]['violator_info']) { new_report[region][violator_id]['violator_info'] = {} };
                if (!new_report[region][violator_id]['violations']) { new_report[region][violator_id]['violations'] = {} };
                if (!new_report[region][violator_id]['violations'][ruleid]) { new_report[region][violator_id]['violations'][ruleid] = {} };

                new_report[region][violator_id]['violator_info']['id'] = violator_id;
                new_report[region][violator_id]['violations'][ruleid].service = service;
                new_report[region][violator_id]['violations'][ruleid].display_name = display_name;
                new_report[region][violator_id]['violations'][ruleid].description = description;
                new_report[region][violator_id]['violations'][ruleid].category = category;
                new_report[region][violator_id]['violations'][ruleid].suggested_action = suggested_action;
                new_report[region][violator_id]['violations'][ruleid].level = level;
                new_report[region][violator_id]['violations'][ruleid].include_violations_in_count = include_violations_in_count;
                new_report[region][violator_id]['violations'][ruleid].region = region;
                new_report[region][violator_id]['violations'][ruleid].result_info = result_info;
                new_report[region][violator_id]['violations'][ruleid].meta_cis_id = meta_cis_id;
                new_report[region][violator_id]['violations'][ruleid].meta_cis_level = meta_cis_level;
                new_report[region][violator_id]['violations'][ruleid].meta_always_show_card = true;

            }
        }
    }

    callback(new_report);
  EOH
end

coreo_uni_util_variables "update-plandwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner.usage.report' => 'COMPOSITE::coreo_uni_util_jsrunner.usage.return'},
            ])
end

coreo_uni_util_jsrunner "inspector-tags-to-notifiers-array" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.10.7-beta64"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }       ])
  json_input '{ "compositeName":"PLAN::stack_name",
                "planName":"PLAN::name",
                "teamName":"PLAN::team_name",
                "cloudAccountName": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_aws_rule_runner.advise-inspector.report}'
  function <<-EOH

const compositeName = json_input.compositeName;
const planName = json_input.planName;
const cloudAccount = json_input.cloudAccountName;
const cloudObjects = json_input.violations;
const teamName = json_input.teamName;

const NO_OWNER_EMAIL = "${AUDIT_AWS_INSPECTOR_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_INSPECTOR_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_INSPECTOR_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_INSPECTOR_SEND_ON}";
const htmlReportSubject = "${HTML_REPORT_SUBJECT}";

const alertListArray = ${AUDIT_AWS_INSPECTOR_ALERT_LIST};
const ruleInputs = {};

let userSuppression;
let userSchemes;

const fs = require('fs');
const yaml = require('js-yaml');

function setSuppression() {
  try {
      userSuppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
    if (e.name==="YAMLException") {
      throw new Error("Syntax error in suppression.yaml file. "+ e.message);
    }
    else{
      console.log(e.name);
      console.log(e.message);
      userSuppression=[];
    }
  }

  coreoExport('suppression', JSON.stringify(userSuppression));
}

function setTable() {
  try {
    userSchemes = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
    if (e.name==="YAMLException") {
      throw new Error("Syntax error in table.yaml file. "+ e.message);
    }
    else{
      console.log(e.name);
      console.log(e.message);
      userSchemes={};
    }
  }

  coreoExport('table', JSON.stringify(userSchemes));
}
setSuppression();
setTable();

const argForConfig = {
    NO_OWNER_EMAIL, cloudObjects, userSuppression, OWNER_TAG,
    userSchemes, alertListArray, ruleInputs, ALLOW_EMPTY,
    SEND_ON, cloudAccount, compositeName, planName, htmlReportSubject, teamName
}


function createConfig(argForConfig) {
    let JSON_INPUT = {
        compositeName: argForConfig.compositeName,
        htmlReportSubject: argForConfig.htmlReportSubject,
        planName: argForConfig.planName,
        teamName: argForConfig.teamName,
        violations: argForConfig.cloudObjects,
        userSchemes: argForConfig.userSchemes,
        userSuppression: argForConfig.userSuppression,
        alertList: argForConfig.alertListArray,
        disabled: argForConfig.ruleInputs,
        cloudAccount: argForConfig.cloudAccount
    };
    let SETTINGS = {
        NO_OWNER_EMAIL: argForConfig.NO_OWNER_EMAIL,
        OWNER_TAG: argForConfig.OWNER_TAG,
        ALLOW_EMPTY: argForConfig.ALLOW_EMPTY, SEND_ON: argForConfig.SEND_ON,
        SHOWN_NOT_SORTED_VIOLATIONS_COUNTER: false
    };
    return {JSON_INPUT, SETTINGS};
}

const {JSON_INPUT, SETTINGS} = createConfig(argForConfig);
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');

const emails = CloudCoreoJSRunner.createEmails(JSON_INPUT, SETTINGS);
const suppressionJSON = CloudCoreoJSRunner.createJSONWithSuppress(JSON_INPUT, SETTINGS);

coreoExport('JSONReport', JSON.stringify(suppressionJSON));
coreoExport('report', JSON.stringify(suppressionJSON['violations']));

callback(emails);
  EOH
end

coreo_uni_util_variables "inspector-update-planwide-3" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.inspector-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.inspector-tags-to-notifiers-array.JSONReport'},
                {'COMPOSITE::coreo_aws_rule_runner.advise-inspector.report' => 'COMPOSITE::coreo_uni_util_jsrunner.inspector-tags-to-notifiers-array.report'},
                {'GLOBAL::table' => 'COMPOSITE::coreo_uni_util_jsrunner.inspector-tags-to-notifiers-array.table'}
            ])
end

coreo_uni_util_jsrunner "inspector-tags-rollup" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.inspector-tags-to-notifiers-array.return'
  function <<-EOH
const notifiers = json_input;

function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    let usedEmails=new Map();
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        const email = notifier['endpoint']['to'];
        if(hasEmail && usedEmails.get(email)!==true) {
            usedEmails.set(email,true);
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['numberOfViolatingCloudObjects'] + ", Cloud Objects: "+ (notifier["num_violations"]-notifier['numberOfViolatingCloudObjects']) + "\\n";
        }
    });

    textRollup += 'Total Number of matching Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;

}


let textRollup = '';
setTextRollup();
callback(textRollup);
  EOH
end

coreo_uni_util_notify "advise-inspector-to-tag-values" do
  action((("${AUDIT_AWS_INSPECTOR_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.inspector-tags-to-notifiers-array.return'
end

coreo_uni_util_notify "advise-ec2-rollup" do
  action((("${AUDIT_AWS_INSPECTOR_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_INSPECTOR_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty ${AUDIT_AWS_INSPECTOR_ALLOW_EMPTY}
  send_on "${AUDIT_AWS_INSPECTOR_SEND_ON}"
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.inspector-tags-rollup.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_INSPECTOR_RECIPIENT}', :subject => 'CloudCoreo ec2 rule results on PLAN::stack_name :: PLAN::name'
  })
end

coreo_aws_s3_policy "cloudcoreo-audit-aws-inspector-policy" do
  action((("${AUDIT_AWS_INSPECTOR_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :create : :nothing)
  policy_document <<-EOF
{
"Version": "2012-10-17",
"Statement": [
{
"Sid": "",
"Effect": "Allow",
"Principal":
{ "AWS": "*" }
,
"Action": "s3:*",
"Resource": [
"arn:aws:s3:::${AUDIT_AWS_INSPECTOR_S3_NOTIFICATION_BUCKET_NAME}/*",
"arn:aws:s3:::${AUDIT_AWS_INSPECTOR_S3_NOTIFICATION_BUCKET_NAME}"
]
}
]
}
  EOF
end

coreo_aws_s3_bucket "${AUDIT_AWS_INSPECTOR_S3_NOTIFICATION_BUCKET_NAME}" do
  action((("${AUDIT_AWS_INSPECTOR_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :create : :nothing)
  bucket_policies ["cloudcoreo-audit-aws-inspector-policy"]
  region "us-east-1"
end

coreo_uni_util_notify "cloudcoreo-audit-aws-inspector-s3" do
  action((("${AUDIT_AWS_INSPECTOR_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :notify : :nothing)
  type 's3'
  allow_empty true
  payload 'COMPOSITE::coreo_uni_util_jsrunner.inspector-tags-to-notifiers-array.report'
  endpoint ({
      object_name: 'aws-inspector-json',
      bucket_name: '${AUDIT_AWS_INSPECTOR_S3_NOTIFICATION_BUCKET_NAME}',
      folder: 'inspector/PLAN::name',
      properties: {}
  })
end
