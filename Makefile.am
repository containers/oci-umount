libexec_PROGRAMS = oci-umount
oci_umount_SOURCES = src/oci-umount.c
oci_umount_DATA = oci-umount.conf
oci_umountdir=/etc

oci_umount_CFLAGS = -Wall -Wextra -std=c99 $(YAJL_CFLAGS)
oci_umount_LDADD = $(YAJL_LIBS)
oci_umount_CFLAGS += $(SELINUX_CFLAGS)
oci_umount_LDADD += $(SELINUX_LIBS)
oci_umount_CFLAGS += $(LIBMOUNT_CFLAGS)
oci_umount_LDADD += $(LIBMOUNT_LIBS)

dist_man_MANS = oci-umount.1
EXTRA_DIST = README.md LICENSE

oci-umount.1: doc/oci-umount.1.md
	go-md2man -in doc/oci-umount.1.md -out oci-umount.1

dist: oci-umount.spec 
	spectool -g oci-umount.spec

rpm: dist
	rpmbuild --define "_sourcedir `pwd`" --define "_specdir `pwd`" \
	--define "_rpmdir `pwd`" --define "_srcrpmdir `pwd`" -ba oci-umount.spec 

clean-local:
	-rm -f oci-umount.1 *~
	-rm -f oci-umount-*.tar.gz
	-rm -f oci-sytemd-hook-*.rpm

