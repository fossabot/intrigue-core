module Intrigue
module Issue
class AtlassianJiraUserDisclosureCve202014181 < BaseIssue

  def self.generate(instance_details={})
    {
      added: "2020-11-23",
      name: "atlassian_jira_user_disclosure_cve_2020_14181",
      pretty_name: "Atlassian Jira User Disclosure (CVE-2020-14181)",
      identifiers: [
        { type: "CVE", name: "CVE-2020-14181" }
      ],
      severity: 4,
      category: "vulnerability",
      status: "confirmed",
      description: "Given a username, the Jira server confirms whether the users profile exists.",
      remediation: "Upgrade your Jira instance",
      affected_software: [ 
        { :vendor => "Atlassian", :product => "Jira" } ],
      references: [ # types: description, remediation, detection_rule, exploit, threat_intel
        { type: "description", uri: "https://jira.atlassian.com/browse/JRASERVER-71560" }
      ],
      check: "vuln/atlassian_jira_user_disclosure_cve_2020_14181"
    }.merge!(instance_details)
  end

end
end
end
