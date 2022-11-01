# Audito Maldito

This is a daemon that reads a system's logs and generates audit events from them.
Currently, it only supports systemd's journal and it outputs logins in JSON format,
as generated by [the auditevent library](https://github.com/metal-toolbox/auditevent).

In the future, we intend to support other audit event types, such as operator
actions in a node.

## Usage

This is meant to be used as a Kubernetes Daemonset. to run it, you need
to mount the following directories for the host:

* `/var/log`
* `/etc/os-release`
* `/etc/machine-id`
* `/var/run/audito-maldito`

## Building

To build the binary in a container, run:

```bash
make image
```

Note that you'll need to have Docker installed.

## Testing

To run the unit tests, you need to have `go` installed and run:

```bash
make unit-test
```

To test the daemon, you can run it locally, and then run the following command:

```bash
LIVE_INSTANCE=<some instance IP> make instance-test
```

This will download the necessary information from a running instance and run
the container locally, using the downloaded information.

Note that given that the journald files may be quite large, this may take a while.
This also won't download them every time. If it detects that the files are already
downloaded, it will use them.

To view the audit logs, you can run:
    
```bash
tail -f live-instance-test/$LIVE_INSTANCE/run/audit.log
```

The `core` user is used by default to download information from a running instance.
If you need to change it, you can do so by setting the `INSTANCE_USER` variable.

To clean the downloaded information, run:

```bash
make clean-instance-test
```