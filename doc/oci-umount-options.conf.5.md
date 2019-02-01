% OCI-UMOUNT-OPTIONS.CONF(5) oci-umount-options.conf

## NAME
oci-umount-options.conf - configuration file for oci-umount hook

## DESCRIPTION
The oci-umount-options.conf file specifies optoins for oci-umount hook.

This file is in ini format. Currently only one section named "options" is supported.

If you want to override any options, don't edit this file. Instead create a new file /etc/oci-umount/oci-umount-options.conf and override options there.

## OPTIONS

**log_level**=""
  The level of logs sent to syslog. Log levels are same as described in syslog(3). Logs of same priority as log_level and higher priority will be sent to syslog and rest will be ignored. By default logs of level LOG_INFO and lower priority (higher importance) are sent to syslog and LOG_DEBUG is not logged. If one wants to enable debug level logs, specify log_level=LOG_DEBUG.