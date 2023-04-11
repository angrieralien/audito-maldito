.PHONY: service
service:
	go run .

.PHONY: image
image:
	docker build -t ghcr.io/metal-toolbox/audito-maldito-rsyslog:v0.0.1 .

.PHONY: rsyslog
rsyslog:
	docker rm -f rsyslog && \
	docker run -d -ti \
	--name rsyslog  \
	-v /run/systemd/journal:/run/systemd/journal \
	-v /var/log/audito-maldito:/var/log/audito-maldito \
	-v /var/run/log:/var/run/log \
	-v ${PWD}/config:/config \
	-v /var/log/audit/:/var/log/audit/ \
	-v /dev/log/:/dev/log \
	-e RSYSLOG_CONF=/config/rsyslog.conf \
	 ghcr.io/metal-toolbox/audito-maldito-rsyslog:v0.0.1


