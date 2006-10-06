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
OBJS     = nsdhcpd.o

include  $(NAVISERVER)/include/Makefile.module

