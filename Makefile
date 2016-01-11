ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Module name
#
MOD      =  nsdhcpd.so

#
# Objects to build.
#
MODOBJS     = nsdhcpd.o

include  $(NAVISERVER)/include/Makefile.module

