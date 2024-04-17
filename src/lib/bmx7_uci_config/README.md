## BMX7_config plugin for OpenWRT universal configuraton interface (UCI)

- Plugin for dynamic interaction with uci 

- To compile first install uci (old version): 
	wget http://downloads.openwrt.org/sources/uci-0.7.5.tar.gz
        sometimes theres an error: edit cli.c # change line 465 to:         char *argv[MAX_ARGS+2];
	tar xzvf uci-0.7.5.tar.gz; cd uci-0.7.5; make; sudo make install

- Alternatively check: http://www.wakoond.hu/2013/06/using-uci-on-ubuntu.html

- Default configuration backend is: /etc/config/bmx7

- see lib/bmx7_config/etc_config for a simple (bmx)
  and an advanced (bmx-advanced) example


