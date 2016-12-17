require 'rspec/core'
require 'rspec/core/rake_task'

#task :default => :spec

desc "System Setup"
task :setup do
  require 'fileutils'

  puts "Setup initiated!"

  # Setup
  intrigue_basedir = File.dirname(__FILE__)

  ## Copy system config into place
  puts "Copying system config...."
  system_config_file = "#{intrigue_basedir}/config/config.json"
  if File.exist? system_config_file
    puts "File exists: #{system_config_file}"
  else
    puts "Creating.... #{system_config_file}"
    FileUtils.cp "#{system_config_file}.default", system_config_file
  end

  ## Copy database config into place
  puts "Copying database config...."
  database_config_file = "#{intrigue_basedir}/config/database.yml"
  if File.exist? database_config_file
    puts "File exists: #{database_config_file}"
  else
    puts "Creating.... #{database_config_file}"
    FileUtils.cp "#{database_config_file}.default", database_config_file
  end

  ## Copy sidekiq task worker config into place
  puts "Setting up task worker config...."
  sidekiq_interactive_config_file = "#{intrigue_basedir}/config/sidekiq-task-interactive.yml"
  sidekiq_autoscheduled_config_file = "#{intrigue_basedir}/config/sidekiq-task-autoscheduled.yml"
  if File.exist? sidekiq_interactive_config_file && sidekiq_autoscheduled_config_file
    puts "File exists: #{sidekiq_interactive_config_file}"
    puts "File exists: #{sidekiq_autoscheduled_config_file}"
  else
    puts "Copying: #{sidekiq_interactive_config_file}.default"
    puts "Copying: #{sidekiq_autoscheduled_config_file}.default"
    FileUtils.cp "#{sidekiq_interactive_config_file}.default", sidekiq_interactive_config_file
    FileUtils.cp "#{sidekiq_autoscheduled_config_file}.default", sidekiq_autoscheduled_config_file
  end
  
  puts "Obtaining latest data..."
  geolocation_database =  "#{intrigue_basedir}/data/geolitecity/latest.dat"
  web_accounts_list =  "#{intrigue_basedir}/data/web_accounts_list/web_accounts_list.json"
  unless File.exist? geolocation_database && web_accounts_list
    puts "Getting data files (will fail if we don't have internet)"
    Dir.chdir("#{intrigue_basedir}/data/"){ puts %x["./get_latest.sh"] }
  end
end

desc "Run Database Migrations"
task :migrate => :setup do

  begin
    require 'yaml'
    require 'json'
    require 'dm-core'
    require 'dm-migrations'
    require 'dm-validations'
    require 'dm-types'

    intrigue_basedir = File.dirname(__FILE__)
    config_file = "#{intrigue_basedir}/config/config.json"

    begin
      system_config = JSON.parse File.read(config_file)
    rescue JSON::ParserError => e
      puts "Fatal! Unable to read #{config_file}"
      return
    end

    database_config = YAML.load_file("#{intrigue_basedir}/config/database.yml")
    database_environment = ENV.fetch('INTRIGUE_ENV', "development")

    unless database_config[database_environment]
      puts "FATAL! Unable to read database configuration"
      return
    end

    Dir["#{intrigue_basedir}/app/models/*.rb"].each { |file| require_relative file }

    # Run our setup with the correct enviroment
    DataMapper::Logger.new($stdout, :debug)
    DataMapper.setup(:default, database_config[database_environment])
    DataMapper.auto_upgrade!
    DataMapper.finalize

    puts "Creating default project..."
    Intrigue::Model::Project.create(:name => "Default") unless Intrigue::Model::Project.first

  rescue Exception => e
    puts "Error... Unable to migrate: #{e}"
  end
end

desc "Prep DB"
task :prep_db do
  DataMapper.repository(:default).adapter.execute("CREATE EXTENSION HSTORE")
end

desc "Run Specs"
task :spec do
end

desc "Run Integration Specs (requires API running)"
task :integration do
  t.rspec_opts = "--pattern spec/integration/*_spec.rb"
end
