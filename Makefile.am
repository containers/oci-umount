libexec_PROGRAMS = oci_systemd_hook
oci_systemd_hook_SOURCES= src/systemdhook.c

oci_systemd_hook_CFLAGS = $(YAJL_CFLAGS)
oci_systemd_hook_LDADD = $(YAJL_LIBS)
oci_systemd_hook_CFLAGS += $(SELINUX_CFLAGS)
oci_systemd_hook_LDADD += $(SELINUX_LIBS)

dist_man_MANS = doc/oci_systemd_hook.1
EXTRA_DIST = README.md LICENSE
