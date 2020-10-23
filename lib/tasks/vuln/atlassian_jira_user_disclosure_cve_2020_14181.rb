module Intrigue
  module Task
  class AtlassianJiraUserDisclosureCve202014181 < BaseTask
  
    def self.metadata
      {
        :name => "vuln/atlassian_jira_user_disclosure_cve_2020_14181",
        :pretty_name => "Vuln Check - Atlassian Jira User Disclosure (CVE-2020-14181)",
        :identifiers => [{ "cve" =>  "CVE-2020-14181" }],
        :authors => ["jcran"],
        :description => "Check for CVE-2020-14181",
        :references => [],
        :type => "vuln_check",
        :passive => false,
        :allowed_types => ["Uri"],
        :example_entities => [ {"type" => "Uri", "details" => {"name" => "https://intrigue.io"}} ],
        :allowed_options => [],
        :created_types => []
      }
    end
  
    ## Default method, subclasses must override this
    def run
      super
  
      # first, ensure we're fingerprinted
      require_enrichment
  
      # craft the URI
      #  https://jira.acme.org:443/secure/ViewUserHover.jspa?username=
      uri = "#{_get_entity_name}/secure/ViewUserHover.jspa?username=#{username}"
      body = http_get_body uri

      if body =~ /<img alt=\"admin\" class=\"avatar-image\"/ 
        _create_linked_issue("atlassian_jira_user_disclosure_cve_2020_14181")
      end
      
    end
  
  end
  end
  end
  