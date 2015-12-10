libexec_PROGRAMS = oci_systemd_hook
oci_systemd_hook_SOURCES= src/systemdhook.c

oci_systemd_hook_CFLAGS = $(YAJL_CFLAGS)
oci_systemd_hook_LDADD = $(YAJL_LIBS)
oci_systemd_hook_CFLAGS += $(SELINUX_CFLAGS)
oci_systemd_hook_LDADD += $(SELINUX_LIBS)

dist_man_MANS = oci_systemd_hook.1
EXTRA_DIST = README.md LICENSE

oci_systemd_hook.1: doc/oci_systemd_hook.1.md
	go-md2man -in doc/oci_systemd_hook.1.md -out oci_systemd_hook.1

clean-local:
	-rm -f oci_systemd_hook.1
