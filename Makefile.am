libexec_PROGRAMS = oci-systemd-hook
oci_systemd_hook_SOURCES= src/systemdhook.c

oci_systemd_hook_CFLAGS = -std=c99 $(YAJL_CFLAGS)
oci_systemd_hook_LDADD = $(YAJL_LIBS)
oci_systemd_hook_CFLAGS += $(SELINUX_CFLAGS)
oci_systemd_hook_LDADD += $(SELINUX_LIBS)
oci_systemd_hook_CFLAGS += $(LIBMOUNT_CFLAGS)
oci_systemd_hook_LDADD += $(LIBMOUNT_LIBS)

dist_man_MANS = oci-systemd-hook.1
EXTRA_DIST = README.md LICENSE

oci-systemd-hook.1: doc/oci-systemd-hook.1.md
	go-md2man -in doc/oci-systemd-hook.1.md -out oci-systemd-hook.1

dist: oci-systemd-hook.spec 
	spectool -g oci-systemd-hook.spec

rpm: dist
	rpmbuild --define "_sourcedir `pwd`" --define "_specdir `pwd`" \
	--define "_rpmdir `pwd`" --define "_srcrpmdir `pwd`" -ba oci-systemd-hook.spec 

clean-local:
	-rm -f oci-systemd-hook.1 *~
	-rm -f oci-systemd-hook-*.tar.gz
	-rm -f oci-sytemd-hook-*.rpm

