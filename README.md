# OCI systemd hooks
==============
OCI systemd hook enables running systemd in docker and [OCI](https://github.com/opencontainers/specs)
compatible runtimes such as runc.

oci-systemd-hook
It reads state over stdin and mounts a tmpfs at /run, /tmp, links in a journal directory from the host and
creates /etc/machine-id file for a container.

This project produces a C binary that can be used with runc and Docker (with minor code changes).
If you clone this branch and build/install `oci-systemd-hook`, a binary will be placed in
`/usr/libexec/oci/hooks.d` named `oci-systemd-hook`. You can change this location by
editing `HOOKSDIR` in the Makefile.

Running Docker or OCI runc containers with this executable, oci-systemd-hook is called just before a container is started and after it is provisioned.  If the CMD to run inside of the container is init or systemd, this hook will configure
the container image to run a systemd environment.

oci-systemd-hook will do the following

* Mount a tmpfs on /run and /tmp
-  If there is content in the container image's /run and /tmp that content will be compied onto the tmpfs.
* Will create a /etc/machine-id based on the the containers UUID
* Will mount the hosts /sys/fs/cgroups file systemd read-only into the container
- /sys/fs/cgroup/systemd will be mounted read/write into the container.

When the container stops, these file systems will be removed.

systemd is expected to be able to run within the container without requiring
the --privileged option.  However you will still need to specify a special --stop signal.

If you created a container image based on a dockerfile like the following:
```
cat Dockerfile
FROM 		RHEL7
ENV container docker
RUN dnf -y install httpd; dnf clean all; systemctl enable httpd; systemctl disable dnf* dnf-makecache.timer
CMD [ "/sbin/init" ]
```

You should be able to execute the following command:

```
docker run -ti --stop-signal=RTMIN+3 httpd
```

If you run this hook along with oci-register-machine oci hook, you will be able
to show the containers journal information on the host, using journalctl.

```
journalctl -M CONTAINER_UUID
```


To build, install, clean-up:

First, **clone** this branch, then:

```
git clone https://github.com/projectatomic/oci-systemd-hook
cd oci-systemd-hook
autoreconf -i
./configure --libexecdir=/usr/libexec/oci/hooks.d
make
make install
```
