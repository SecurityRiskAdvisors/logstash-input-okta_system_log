FROM 383707766587.dkr.ecr.ap-southeast-2.amazonaws.com/kelsiem.com/logstash-input-okta_system_log:develop


FROM 383707766587.dkr.ecr.ap-southeast-2.amazonaws.com/kelsiem.com/kelsiemlogstash
WORKDIR /usr/share/logstash/bin
COPY --from=0 /opt/okta_system_log/logstash-input-okta_system_log-0.1.0.gem /usr/share/logstash/bin
RUN ls -la
RUN /usr/share/logstash/bin/logstash-plugin install logstash-input-okta_system_log-0.1.0.gem

WORKDIR /home/ec2-user