CFLAGS +=	$(CORE_CFLAGS) -g3 -fpic -I../../
LDFLAGS +=	-shared -luci
#-Wl,-soname,bmxd_config 

PLUGIN_NAME =   bmx6_gsf_map

SRC_C = gsf_map.c
SRC_H = gsf_map.h
OBJS= $(SRC_C:.c=.o)

PLUGIN_FULLNAME = $(PLUGIN_NAME).so
PLUGIN_SHORTNAME = $(PLUGIN_NAME).so

LIBDIR = /usr/lib
THISDIR = $(shell pwd )

all:	$(PLUGIN_FULLNAME) Makefile


$(PLUGIN_FULLNAME):	$(OBJS) Makefile
	$(CC) $(LDFLAGS) $(EXTRA_LDFLAGS) $(OBJS) -o $(PLUGIN_FULLNAME) 
	ln -f -s $(THISDIR)/$(PLUGIN_FULLNAME) $(THISDIR)/../$(PLUGIN_FULLNAME)

%.o:	%.c %.h Makefile
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@


clean:
	rm -f *.o *.so
	

install:	all
		mkdir -p $(LIBDIR)
		install -D -m 755 $(PLUGIN_FULLNAME) $(LIBDIR)/$(PLUGIN_FULLNAME); /sbin/ldconfig -n $(LIBDIR)


strip:		all
		strip $(PLUGIN_FULLNAME)
