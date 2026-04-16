
AM_CFLAGS = -Wall -Wextra -O2

# Use $$2 (not $2) because make consumes one $ before invoking awk.
VERSION                         = $(shell awk -F'"' '/^#define VERSION / {print $$2; exit}' $(srcdir)/ntlmv1scan.h)

bin_PROGRAMS    = ntlmv1scan
ntlmv1scan_SOURCES = ntlmv1scan.c ntlmv1scan.h
ntlmv1scan_LDADD   =

ACLOCAL_AMFLAGS = -I build-aux

EXTRA_DIST = \
	ntlmv1scan.8.adoc \
	packaging/debian/changelog \
	packaging/debian/control \
	packaging/debian/rules \
	packaging/debian/source/format \
	packaging/rpm/ntlmv1scan.spec

if USE_ASCIIDOC
# begin of USE_ASCIIDOC

# asciidoc is in Python and used on Fedora and RHEL and cannot generate manpages, so we use xmlto to convert docbooc to manpage
asciidoc = asciidoc

man: ntlmv1scan.8

ntlmv1scan.8.xml: ntlmv1scan.8.adoc
	$(asciidoc) -b docbook -d manpage $<

ntlmv1scan.8: ntlmv1scan.8.xml
	xmlto man $<
else
man:
	@test -f ntlmv1scan.8 || { \
		echo "error: ntlmv1scan.8 is missing and asciidoc/xmlto are unavailable to rebuild it"; \
		exit 1; \
	}
endif
# end of USE_ASCIIDOC

.PHONY: rpm deb

rpm: dist
	@command -v rpmbuild >/dev/null 2>&1 || { \
		echo "error: rpmbuild is required to build RPM packages"; \
		exit 1; \
	}
	@rm -rf $(abs_builddir)/rpmbuild
	@mkdir -p $(abs_builddir)/rpmbuild/SPECS $(abs_builddir)/rpmbuild/SOURCES
	@cp $(srcdir)/packaging/rpm/ntlmv1scan.spec $(abs_builddir)/rpmbuild/SPECS/
	@cp $(PACKAGE)-$(VERSION).tar.gz $(abs_builddir)/rpmbuild/SOURCES/
	@cp $(srcdir)/ntlmv1scan.h $(abs_builddir)/rpmbuild/SOURCES/
	@rpmbuild -ba $(abs_builddir)/rpmbuild/SPECS/ntlmv1scan.spec \
		--define "_topdir $(abs_builddir)/rpmbuild"

deb: dist
	@command -v dpkg-buildpackage >/dev/null 2>&1 || { \
		echo "error: dpkg-buildpackage is required to build DEB packages"; \
		exit 1; \
	}
	@rm -rf $(abs_builddir)/debbuild
	@mkdir -p $(abs_builddir)/debbuild
	tar -xzf $(PACKAGE)-$(VERSION).tar.gz -C $(abs_builddir)/debbuild
	@cp -a $(srcdir)/packaging/debian $(abs_builddir)/debbuild/$(PACKAGE)-$(VERSION)/debian
	cd $(abs_builddir)/debbuild/$(PACKAGE)-$(VERSION) && dpkg-buildpackage -us -uc -b
