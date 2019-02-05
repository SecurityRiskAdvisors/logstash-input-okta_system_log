FROM jruby

RUN apt-get update && apt-get upgrade -y

RUN find / | egrep \/bin\/bundle$



RUN mkdir -p /opt/okta_system_log
COPY /* /opt/okta_system_log/
WORKDIR /opt/okta_system_log
RUN ls -la /opt/okta_system_log


RUN bundle install

RUN mkdir -p /opt/efs/plugins