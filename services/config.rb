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

# coreo_aws_rule "ec2-inventory" do
#   action :define
#   service :ec2
#   link ""
#   display_name "Inventory of EC2 (non-spot) Instances"
#   description "An inventory of EC2 (non-spot) Instances"
#   category "Inventory"
#   suggested_action "N/A"
#   level "Informational"
#   objectives ["instances"]
#   audit_objects ["object.reservations.instances.state.name"]
#   operators ["=="]
#   raise_when ["running"]
#   id_map "object.reservations.instances.instance_id"
# end

coreo_aws_rule_runner "usage" do
  action :run
  service :inspector
  rules [
            "inspector-findings"
        ]
end

coreo_uni_util_jsrunner "usage" do
  action :run
  json_input 'COMPOSITE::coreo_aws_rule_runner.usage.report'
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

coreo_uni_util_variables "findings-var" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner.usage.report' => 'COMPOSITE::coreo_uni_util_jsrunner.usage.return'},
            ])
end
