module Intrigue
    module Task
    class RucleiRunner < BaseTask
    
      def self.metadata
        {
          :name => "ruclei_runner",
          :pretty_name => "Ruclei Task Runner",
          :authors => ["shpend"],
          :description => "Runs ruclei template against target",
          :references => [],
          :type => "vuln_check",
          :passive => false,
          :allowed_types => ["Uri"],
          :example_entities => [{"type" => "Uri", "details" => {"name" => "https://intrigue.io"}}],
          :allowed_options => [{ :name => "template", :regex => "filename", :default => "CVE-2020-0000.yaml" }],
          :created_types => []
        }
      end
    
      ## Default method, subclasses must override this
      def run
        super
    
        uri = _get_entity_name
        template = _get_option("template")

        puts "I am running #{template} against #{uri}"
        _create_linked_issue "ruclei_test_issue"

      end
    
    end
    end
    end
    