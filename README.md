# OCI systemd hooks
==============
OCI systemd hook enables running systemd in docker and [OCI](https://github.com/opencontainers/specs)
compatible runtimes such as runc.

It reads state over stdin and mounts a tmpfs at /run, /tmp, links in a journal directory from the host and
creates /etc/machine-id file for a container.

Installation
---------------
```
git clone https://github.com/mrunalp/hooks
cd hooks
autoreconf -i
./configure --libexecdir=/usr/libexec/docker/hooks.d
make
make install
```
