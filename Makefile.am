
AM_CFLAGS = -Wall -Wextra -O2

# Use $$2 (not $2) because make consumes one $ before invoking awk.
VERSION                         = $(shell awk -F'"' '/^#define VERSION / {print $$2; exit}' $(srcdir)/ntlmv1scan.h)

bin_PROGRAMS    = ntlmv1scan
ntlmv1scan_SOURCES = ntlmv1scan.c ntlmv1scan.h
ntlmv1scan_LDADD   =

ACLOCAL_AMFLAGS = -I build-aux

EXTRA_DIST = ntlmv1scan.8.adoc

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
