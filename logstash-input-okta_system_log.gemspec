Gem::Specification.new do |s|
  s.name          = 'logstash-input-okta_system_log'
  s.version       = '0.10.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'This plugin fetches log events from Okta using the System Log API'
  s.homepage      = 'https://github.com/SecurityRiskAdvisors/logstash-input-okta_system_log'
  s.authors       = ['Security Risk Advisors']
  s.email         = 'security@securityriskadvisors.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "input" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", ">= 1.60", "<= 2.99"
  s.add_runtime_dependency 'logstash-codec-plain'
  s.add_runtime_dependency 'stud', "~> 0.0.22"
  #s.add_runtime_dependency 'logstash-mixin-http_client', "~> 7" # Retaining logstash 7x compat
  #s.add_runtime_dependency 'logstash-mixin-http_client', ">= 6.0.0", "< 7.0.0" # Retaining logstash 5/6x compat
  #s.add_runtime_dependency 'logstash-mixin-http_client', ">= 2.2.4", "< 3.0.0" # Retaining logstash 2.4 compat
  s.add_runtime_dependency 'logstash-mixin-http_client', ">= 2.2.4", "< 8.0.0" # Production versions
  s.add_runtime_dependency 'rufus-scheduler', "~>3.0.9"

  s.add_development_dependency 'logstash-codec-json'
  s.add_development_dependency 'logstash-codec-line'
  s.add_development_dependency 'logstash-devutils', '>= 0.0.16'
  s.add_development_dependency 'flores'
  s.add_development_dependency 'timecop'

end
