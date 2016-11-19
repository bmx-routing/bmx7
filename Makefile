# Copyright (c) 2010-2016  BMX protocol contributors
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA

include Common.mk


all:	
	$(MAKE) $(BINARY_NAME)
	# further make targets: help, libs, build_all, strip[_libs|_all], install[_libs|_all], clean[_libs|_all]

libs:	all
	$(MAKE)  -C lib all CORE_CFLAGS='$(CFLAGS)'


$(BINARY_NAME):	$(OBJS) Makefile Common.mk
	$(CC)  $(OBJS) -o $@  $(LDFLAGS) $(EXTRA_LDFLAGS)

%.o:	%.c %.h Makefile Common.mk $(SRC_H)
	$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -c $< -o $@

strip:	all
	strip $(BINARY_NAME)

strip_libs: all libs
	$(MAKE) -C lib strip

install:	all
	mkdir -p $(SBINDIR)
	install -m 0755 $(BINARY_NAME) $(SBINDIR)

install_libs:   all
	$(MAKE) -C lib install CORE_CFLAGS='$(CFLAGS)'


clean:
	rm -f $(BINARY_NAME) *.o posix/*.o linux/*.o

clean_libs:
	$(MAKE) -C lib clean


clean_all: clean clean_libs
build_all: all libs
strip_all: strip strip_libs
install_all: install install_libs


help:
	# see also http://bmx6.net/projects/bmx6/wiki
	#
	# further make targets:
	# help					show this help
	# all					compile  bmx7 core only
	# libs			 		compile  bmx7 plugins
	# build_all				compile  bmx7 and plugins
	# strip / strip_libs / strip_all	strip    bmx7 / plugins / all
	# install / install_libs / install_all	install  bmx7 / plugins / all
	# clean / clean_libs / clean_all	clean    bmx7 / libs / all
	#
	# minimum compile requirements are zlib and polarssl libraries:
	#
	# for polarssl on debian do:
	#   apt-get install libpolarssl-dev
	#
	# for zlib on debian do:
	#   apt-get install zlib1g-dev
	#
	#   

