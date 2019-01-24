% OCI-UMOUNT.CONF(5) oci-umount.conf
## NAME
oci-umount.conf - oci-umount configuration file

## DESCRIPTION
The oci-umount.conf file contains a list of paths on host which will be unmounted inside container. (If they are mounted inside container).

## FORMAT
If there is a "/*" at the end, that means only mounts underneath that mounts (submounts) will be unmounted but top level mount will remain in place.

## EXAMPLES

```
/var/lib/docker/overlay2
/var/lib/docker/overlay
/var/lib/docker/devicemapper
/var/lib/docker/containers/*
/var/lib/docker-latest/overlay2
/var/lib/docker-latest/overlay
/var/lib/docker-latest/devicemapper
/var/lib/docker-latest/containers/*
/var/lib/containers/storage/*
/run/containers/storage/*
/var/lib/origin/*
```

