FROM 383707766587.dkr.ecr.ap-southeast-2.amazonaws.com/kelsiem.com/logstash-input-okta_system_log:base

RUN find / | egrep \/bin\/bundle$



RUN mkdir -p /opt/okta_system_log


COPY / /opt/okta_system_log/
WORKDIR /opt/okta_system_log
RUN ls -la /opt/okta_system_log


RUN bundle install

RUN bundle exec rspec
RUN gem build logstash-input-okta_system_log.gemspec


RUN gem unpack logstash-input-okta_system_log-0.1.0.gem
RUN ls -laR logstash-input-okta_system_log-0.1.0
