FROM ubuntu
RUN apt update
RUN apt install rsyslog -y
ENTRYPOINT ["rsyslogd", "-d", "-n", "-f", "/config/rsyslog.conf"]