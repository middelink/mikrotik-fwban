# Mikrotik-fwban

[![Build Status](https://travis-ci.org/middelink/mikrotik-fwban.svg?branch=master)](https://travis-ci.org/middelink/mikrotik-fwban)
[![GoDoc](https://godoc.org/github.com/middelink/mikrotik-fwban?status.svg)](https://godoc.org/github.com/middelink/mikrotik-fwban)

* Command mikrotik-fwban acts as a syslog receiver and tries to extract an
  IP address out of the messages received. It then adds the IPs to the
  banlist on the configured Mikrotiks. In essence it is a Fail2Ban done the
  lazy way. Since it leverages the filtering mechanisms of rsyslog to do the
  pre-filtering, it should be able to handle large sets of publicly
  accessable machines (famous last words, I know).
* It handles both IPv4 and IPv6 addresses and banlists.
* It can handle multiple Mikrotiks, keeping the banned IPs in their
  respective banlists in sync.

## Config file

Seems kind of self explanatory so I'm not going to explain every item
in it.

Remember you can use the same configurations in the central settings
as in the Command Line.

It is possible to administer more than one Mikrotik by using separate
sections for each one. Perfect if you want to manage all Mikrotiks
for your family, remote office locations or customers. You can still
use different permanent whitelists and blacklists for each Mikrotik.

## Command Line Flags

* `--blocktime`: Set the life time for dynamically managed entries. The
  MikroTik will be told to remove the entry from the blacklist after
  this many hours. If autodelete is true mikrotik-fwban will take care
  of the deletion. Default is 1 week.
* `--filename`: Path of the configuration file to read. Default is
  /etc/mikrotik-fwban.cfg.
* `--port`: UDP port we listen on for syslog formatted messages.
  Default is 10514.
* `--autodelete`: Autodelete entries when they expire. Aka, don't trust
  Mikrotik to do it for us. Default is true.
* `--verbose`: Be more verbose in our logging. Default is false.
* `--debug`: Be absolutely staggering in our logging. Default is false.

## Installation

I presume you have a working experiance with go, a system with systemd
and rsyslogd and in general some sys admin knowledge as I am not able
to support you with questions on every conveivable way to build, install
and start this daemon at startup.

### Building the binary

* Clone, download, copy/paste the source files onto your local disk.
* Execute `go build .` to create the mikrotik-fwban binary.
* Copy the binary to /usr/local/sbin.

### Mikrotik changes

* Create a group (`apis`) on your mikrotik (system > users; groups) and
  give it at least the `read`, `write` and `api` policies.
* Create a user on your mikrotik (system > users; users) and have it
  belong to the group you just created.
* Make sure you have rules in your mikrotik (input AND forward) to drop
  traffic coming from src ips in the `banlist` addresslist.

### Setup your system.

* Copy `mikrotik-fwban.cfg` to /etc/ and edit to your liking.
* Copy `mikrotik-fwban.service` to /etc/systemd/system/
* Execute `systemctl daemon-reload`.
* Execute `systemctl enable mikrotik-fwban` to enable the daemon at startup.
* Execute `systemctl start mikrotik-fwban` to start the daemon right now.
* Check your /var/log/messages for possible errors and fix them.
* (If you want to receive syslog messages from other than the local machine,
  don't forget to open your firewall on the configured port.)

### Sending syslog information its way.

* Add a snippet to /etc/rsyslog.d to (re)send interesting messages to the
  mikrotik port, best thing is to filter on error conditions containing an
  IP you want to block. Example below:

  ```
  if re_match($msg, "failed for '[0-9a-f:.]*' - Wrong password") then
	action(type="omfwd" target="<mikrotik-fwban-ip>" port="<mikrotik-fwban-port>" template="RSYSLOG_SyslogProtocol23Format")
  ```

  Remember to put in the target IP address and port of your Mikrotik-fwban's
  host.

* Restart your rsyslogd to make sure it loaded the fragment.
* You can do this on every Unix system in your network if you feel so
  inclined. Again, don't forget to open the firewall on the Mikrotik-fwban's
  host if you do.

## Credits

Mikrotik-fwban uses
[go-gcfg](https://github.com/go-gcfg/gcfg/tree/v1),
[syslogparser](github.com/jeromer/syslogparser),
[routeros-api-go](https://github.com/Netwurx/routeros-api-go)

