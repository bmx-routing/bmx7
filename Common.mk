GIT_REV ?= $(shell [ -r .git ] && git --no-pager log -n 1 --oneline | cut -d " " -f 1 || echo 0)

CFLAGS += -pedantic -W -Wall -Wstrict-prototypes -Wno-unused-parameter -Os -g3 -std=gnu99 -DGIT_REV=\"$(GIT_REV)\"
# CFLAGS += -DHAVE_CONFIG_H
# CFLAGS += -DCRYPTLIB=POLARSSL_1_3_4 # POLARSSL_1_2_5 POLARSSL_1_2_9 POLARSSL_1_3_3 POLARSSL_1_3_4 CYASSL_2_8_0

# optinal defines:
# CFLAGS += -static
# CFLAGS += -pg # "-pg" with openWrt causes "gcrt1.o: No such file"! Needs ld -o myprog /lib/gcrt0.o myprog.o utils.o -lc_p, grep: http://www.cs.utah.edu/dept/old/texinfo/as/gprof.html

# paranoid defines (helps bug hunting during development):
# CFLAGS += -DEXTREME_PARANOIA -DEXIT_ON_ERROR -DPROFILING

# CFLAGS += -DNO_KEY_GEN  # use openssl instead, like:
                          # openssl genrsa -out /etc/bmx7/rsa.pem 1024
                          # openssl rsa -in /etc/bmx7/rsa.pem -inform PEM -out /etc/bmx7/rsa.der -outform DER

# Some test cases:
# CFLAGS += -DTEST_LINK_ID_COLLISION_DETECTION
# CFLAGS += -DTEST_DEBUG          # (testing syntax of __VA_ARGS__ dbg...() macros)
# CFLAGS += -DTEST_DEBUG_MALLOC   # allocates a never freed byte which should be reported at bmx7 termination
# CFLAGS += -DAVL_5XLINKED -DAVL_DEBUG -DAVL_TEST
CFLAGS += -DAVL_5XLINKED

# optional defines (you may disable these features if you dont need them)
# CFLAGS += -DNO_DEBUG_TRACK
# CFLAGS += -DNO_DEBUG_SYS
# CFLAGS += -DLESS_OPTIONS
# CFLAGS += -DNO_DYN_PLUGIN
# CFLAGS += -DNO_TRACE_FUNCTION_CALLS

# CFLAGS += -DDEBUG_ALL
# CFLAGS += -DTRAFFIC_DUMP
# CFLAGS += -DDEBUG_DUMP
# CFLAGS += -DDEBUG_MALLOC
# CFLAGS += -DMEMORY_USAGE

# experimental or advanced defines (please dont touch):
# CFLAGS += -DNO_ASSERTIONS       # (disable syntax error checking and error-code creation!)
# CFLAGS += -DEXTREME_PARANOIA    # (check difficult syntax errors)
# CFLAGS += -DEXIT_ON_ERROR       # (exit and return code due to unusual behavior)
# CFLAGS += -DTEST_DEBUG
# CFLAGS += -DWITH_UNUSED         # (includes yet unused stuff and buggy stuff)
# CFLAGS += -DPROFILING           # (no static functions -> better profiling and cores)
# CFLAGS += -DNO_CTAOCRYPT_DIR    # for backward compatibility with old cyassl versions
# CFLAGS += -DCORE_LIMIT=20000    # equals ulimit -c 20000

#EXTRA_CFLAGS +=
#EXTRA_LDFLAGS +=

# add as much features and test cases as possible:
#EXTRA_CFLAGS += -DMOST

#for profiling:
#EXTRA_CFLAGS="-DPROFILING -pg"

#for very poor embedded stuff (reducing binary size and cpu footprint):
#EXTRA_CFLAGS="-DNO_DEBUG_TRACK -DNO_TRACE_FUNCTION_CALLS -DNO_ASSERTIONS"

#for small embedded stuff the defaults are just fine.

#for normal machines (adding features and facilitating debugging):
#EXTRA_CFLAGS="-DDEBUG_ALL -DTRAFFIC_DUMP -DDEBUG_DUMP -DEBUG_MALLOC -DMEMORY_USAGE"

CFLAGS += $(shell echo "$(EXTRA_CFLAGS)" | grep -q "DMOST" && echo "-pg -DCORE_LIMIT=20000 -DEXTREME_PARANOIA -DPROFILING -DDEBUG_ALL -DTRAFFIC_DUMP -DDEBUG_DUMP -DDEBUG_MALLOC -DMEMORY_USAGE " )

LDFLAGS += -g3

LDFLAGS += $(shell echo "$(CFLAGS) $(EXTRA_CFLAGS)" | grep -q "DNO_DYN_PLUGIN" || echo "-Wl,-export-dynamic -ldl" )
LDFLAGS += $(shell echo "$(CFLAGS) $(EXTRA_CFLAGS)" | grep -q "DPROFILING" && echo "-pg -lc" )
LDFLAGS += $(shell echo "$(CFLAGS) $(EXTRA_CFLAGS)" | grep -q "DBMX7_LIB_IWINFO" && echo "-liwinfo" || echo "-liw" )

LDFLAGS += -lz -lm
LDFLAGS += $(shell echo "$(CFLAGS) $(EXTRA_CFLAGS)" | grep -q "CYASSL" && echo "-lcyassl" || echo "-lpolarssl")

SBINDIR = $(INSTALL_PREFIX)/usr/sbin

SRC_C =  bmx.c key.c node.c crypt.c sec.c content.c msg.c z.c iid.c desc.c metrics.c ogm.c link.c iptools.c tools.c plugin.c list.c allocate.c avl.c hna.c control.c schedule.c ip.c prof.c
SRC_H =  bmx.h key.h node.h crypt.h sec.h content.h msg.h z.h iid.h desc.h metrics.h ogm.h link.h iptools.h tools.h plugin.h list.h allocate.h avl.h hna.h control.h schedule.h ip.h prof.h

SRC_C += $(shell echo "$(CFLAGS) $(EXTRA_CFLAGS)" | grep -q "DTRAFFIC_DUMP" && echo dump.c )
SRC_H += $(shell echo "$(CFLAGS) $(EXTRA_CFLAGS)" | grep -q "DTRAFFIC_DUMP" && echo dump.h )

OBJS = $(SRC_C:.c=.o)

PACKAGE_NAME := bmx7
BINARY_NAME  := bmx7
