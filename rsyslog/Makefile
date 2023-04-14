.PHONY: service
service:
	go run .

.PHONY: image
image:
	docker build -t ghcr.io/metal-toolbox/audito-maldito-rsyslog:v0.0.1 .

.PHONY: rsyslog
rsyslog:
	docker rm -f rsyslog && \
	docker run  -ti \
	--name rsyslog  \
	-v /run/systemd/journal:/run/systemd/journal \
	-v /var/log:/var/log\
	-v /etc/machine-id:/etc/machine-id:ro
	 ghcr.io/metal-toolbox/audito-maldito-rsyslog:v0.0.1


