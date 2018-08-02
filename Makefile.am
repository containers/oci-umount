libexec_PROGRAMS = oci-umount
oci_umount_SOURCES = src/oci-umount.c
oci_umount_DATA = oci-umount.conf
oci_umountdir=/etc

oci_umount_json_CONFIG = oci-umount-json
oci_umount_json_DATA = oci-umount.json
oci_umount_jsondir=/usr/share/containers/oci/hooks.d

oci_umount_options_DATA = oci-umount-options.conf
oci_umount_optionsdir=/usr/share/oci-umount/

oci_umount_CFLAGS = -Wall -Wextra -std=c99 $(JANSSON_CFLAGS)
oci_umount_LDADD = $(JANSSON_LIBS)

dist_man_MANS = oci-umount.1
EXTRA_DIST = README.md LICENSE

oci-umount.1: doc/oci-umount.1.md
	go-md2man -in doc/oci-umount.1.md -out oci-umount.1

spec: oci-umount.spec
	spectool -g oci-umount.spec

rpm: spec
	rpmbuild --define "_sourcedir `pwd`" --define "_specdir `pwd`" \
	--define "_rpmdir `pwd`" --define "_srcrpmdir `pwd`" -ba oci-umount.spec 

install-data-local:
	$(MKDIR_P) $(DESTDIR)/etc/containers/oci/hooks.d
	$(MKDIR_P) $(DESTDIR)/usr/share/oci-umount/oci-umount.d

clean-local:
	-rm -f oci-umount.1 *~
	-rm -f oci-umount-*.tar.gz
	-rm -f oci-sytemd-hook-*.rpm

