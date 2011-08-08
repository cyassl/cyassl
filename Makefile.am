# includes append to these:
SUFFIXES =
TESTS =
CLEANFILES =
DISTCLEANFILES =
bin_PROGRAMS =
noinst_HEADERS =
lib_LTLIBRARIES =
man_MANS =
noinst_LTLIBRARIES =
noinst_PROGRAMS =
include_HEADERS =
nobase_include_HEADERS =
check_PROGRAMS =
EXTRA_HEADERS =
BUILT_SOURCES=
EXTRA_DIST=
doc_DATA=

noinst_PROGRAMS+= ${check_PROGRAMS}

exampledir = $(docdir)/@PACKAGE@/example
example_DATA=
EXTRA_DIST+= $(example_DATA)

certsdir = $(sysconfdir)/ssl/certs
certs_DATA=
EXTRA_DIST+= $(certs_DATA)

EXTRA_DIST+= $(doc_DATA)

ACLOCAL_AMFLAGS= -I m4

EXTRA_DIST+= lib/dummy

EXTRA_DIST+= cyassl-ntru.vcproj
EXTRA_DIST+= cyassl.vcproj
EXTRA_DIST+= cyassl-iphone.xcodeproj/project.pbxproj
EXTRA_DIST+= cyassl-ntru.sln
EXTRA_DIST+= cyassl.sln

include cyassl/include.am
include openssl/include.am
include certs/include.am
include doc/include.am
include swig/include.am

include src/include.am
include ctaocrypt/benchmark/include.am
include ctaocrypt/src/include.am
include ctaocrypt/test/include.am
include examples/client/include.am
include examples/server/include.am
include examples/echoclient/include.am
include examples/echoserver/include.am
include testsuite/include.am
include sslSniffer/sslSnifferTest/include.am

TESTS += $(check_PROGRAMS)
test: check

# !!!! first line of rule has to start with a hard (real) tab, not spaces
basic: src/libcyassl.la testsuite/testsuite $(check_PROGRAMS)

egs: examples/client/client examples/echoclient/echoclient examples/server/server examples/echoserver/echoserver

ctc: ctaocrypt/test/test ctaocrypt/benchmark/benchmark

openssl-links:
	cd lib; ln -s ../src/.libs/libcyassl.a libcrypto.a; \
	  ln -s ../src/.libs/libcyassl.a libssl.a; \
	  ln -s ../src/.libs/libcyassl.a libcyassl.a; cd ../

merge-clean:
	@find ./ | $(GREP) \.gcda | xargs rm -f
	@find ./ | $(GREP) \.gcno | xargs rm -f
	@find ./ | $(GREP) \.gz | xargs rm -f
	@find ./ | $(GREP) \.orig | xargs rm -f
	@find ./ | $(GREP) \.rej | xargs rm -f
	@find ./ | $(GREP) \.rpm | xargs rm -f
	@find ./ | $(GREP) \.THIS | xargs rm -f
	@find ./ | $(GREP) \.OTHER | xargs rm -f
	@find ./ | $(GREP) \.BASE | xargs rm -f
	@find ./ | $(GREP) \~$$ | xargs rm -f
