FROM ubuntu
RUN apt update
RUN apt install rsyslog -y
RUN rm -r /etc/rsyslog.d && mkdir /etc/rsyslog.d
COPY config/rsyslog.d/* /etc/rsyslog.d/
RUN ls /etc/rsyslog.d
ENTRYPOINT ["rsyslogd", "-n", "-f", "config/rsyslog.conf"]