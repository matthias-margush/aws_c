AM_CFLAGS=-g -Wall -Werror -O3 --std=c11 -pedantic-errors -Wstrict-prototypes
bin_PROGRAMS = aws
nobase_include_HEADERS = aws_creds.h
aws_SOURCES = aws.c aws_sig.c aws_creds.c
aws_CFLAGS = $(CURL_CFLAGS) $(OPENSSL_CFLAGS)
aws_LDADD = $(CURL_LIBS) $(OPENSSL_LIBS)
