module Intrigue
    module Issue
    class RucleiTestIssue < BaseIssue
    
      def self.generate(instance_details={})
        {
          added: "2020-01-01",
          name: "ruclei_test_issue",
          pretty_name: "Ruclei Test Issue CVE-2020-0000",
          severity: 1,
          category: "vulnerability",
          status: "confirmed",
          description:"A test issue that works with Ruclei",
          affected_software: [ 
            { :vendor => "Cisco", :product => "Adaptive Security Appliance Software" },
          { :vendor => "Cisco", :product => "Adaptive Security Appliance Device Manager" }
          ],
          references: [ # types: description, remediation, detection_rule, exploit, threat_intel
            { type: "description", uri: "https://intrigue.io" }
          ], 
          check: "ruclei/this_is_a_test.yaml"
        }.merge!(instance_details)
      end
    
    end
    end
    end
    