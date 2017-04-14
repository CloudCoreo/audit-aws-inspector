coreo_aws_rule "inspector-findings" do
  action :define
  service :inspector
  display_name "Reserved instances purchased and unused"
  description "This rule checks for any active and purchased reserved instances that are not covering any RIs"
  category "Spend"
  suggested_action "Consider launching instances with RI coverage"
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

    callback(json_input);

  EOH
end

# coreo_uni_util_variables "findings-var" do
#   action :set
#   variables([
#                 {'COMPOSITE::coreo_aws_rule_runner.usage.report' => 'COMPOSITE::coreo_uni_util_jsrunner.usage.report'},
#             ])
# end
