Gem::Specification.new do |s|
  s.name          = 'logstash-input-okta_system_log'
  s.version       = '1.0.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'Okta System Log Input Plugin'
  s.description   = 'Logstash Plugin to pull Okta System Logs using HTTPS'
  s.homepage      = 'https://github.com/SecurityRiskAdvisors/logstash-input-okta_system_log'
  s.authors       = ['Security Risk Advisors', 'zaakiy']
  s.email         = 'zak@kelsiem.com'
  s.require_paths = ['lib',"lib/logstash/inputs","spec/inputs"]

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "input" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_runtime_dependency 'logstash-codec-plain'
  s.add_runtime_dependency 'stud', '>= 0.0.22'
  s.add_runtime_dependency 'logstash-mixin-http_client', ">= 2.2.4", "< 7.0.0" # Logstash Production
  s.add_runtime_dependency 'manticore', ">=0.6.1"
  s.add_runtime_dependency 'rufus-scheduler', "~>3.0.9"

  s.add_development_dependency 'logstash-devutils', '>= 1.3.6'
  s.add_development_dependency 'logstash-codec-json'
  s.add_development_dependency 'flores'
  s.add_development_dependency 'timecop'
  s.add_development_dependency 'rake', "~> 12.1.0"
  s.add_development_dependency 'kramdown', "~> 1.14.0"

end