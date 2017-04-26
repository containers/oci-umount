## OCI Umount

`oci-umount` is a OCI hook program that will umount any file systems listed in /etc/oci-umount.conf
file before starting a container.  The goal with this tool is to help prevent container mount
space leaking into other containers.


This project produces a golang that can be used with container runtimes and runc (with minor code changes).
If you clone this branch and build/install `umount.go`, a binary will be placed in
`/usr/libexec/oci/hooks.d` named `oci-umount`. You can change this location by
editing `HOOKSDIR` in the Makefile.


With minor changes to upstream docker code, this binary will be executed when starting a
containers via prestart hooks.  

Running runc containers with this executable, oci-umount() is called
just before a container is started and after it is provisioned.

This doc assumes you are running at least docker version 1.12 with the dockerhooks patch.
Also, place this project in your `GOPATH`.


To build, install, clean-up:

First, **clone** this branch in your `GOPATH`, then:

`make build`


`make install`


`make clean`
