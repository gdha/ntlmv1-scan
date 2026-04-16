
AM_CFLAGS = -Wall -Wextra -O2

bin_PROGRAMS    = ntlmv1scan
ntlmv1scan_SOURCES = ntlmv1scan.c ntlmv1scan.h
ntlmv1scan_LDADD   =

ACLOCAL_AMFLAGS = -I build-aux

EXTRA_DIST = ntlmv1scan.8.adoc

if USE_ASCIIDOC
asciidoc = asciidoc

dist_man_MANS = ntlmv1scan.8

ntlmv1scan.8.xml: ntlmv1scan.8.adoc
	$(asciidoc) -b docbook -d manpage $<

ntlmv1scan.8: ntlmv1scan.8.xml
	xmlto man $<
endif
