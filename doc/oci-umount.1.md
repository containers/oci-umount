% OCI-UMOUNT(1) oci-umount
% May 2017
## NAME
oci-umount - Umount mountpints defined in /etc/oci-umount.conf systems before containers start

## SYNOPSIS

**oci-umount**

## DESCRIPTION

`oci-umount` is a OCI hook program. If you add it to the runc json data
as a hook, runc will execute the application after the container process is created but before it is executed, with a `prestart` flag.
Docker will execute `oci-umount` as a container hook when it is installed in the $HOOKSDIR directory.

You can setup the file systems to umount by editing the /etc/oci-umount.conf

## EXAMPLES

	$ docker run -it busybox /bin/sh

	(In different terminal):
	
## SEE ALSO

docker-run(1)

## HISTORY
May 2017, written by Dan Walsh <dwalsh@redhat.com>
