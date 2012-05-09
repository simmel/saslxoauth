CFLAGS=-I/usr/include/sasl -g
LDFLAGS=-lsasl2

all: libxoauth.so.2.0.22
plugin_common.lo: plugin_common.c
	gcc -DHAVE_CONFIG_H -I. -I/usr/include/sasl -Wall -W -g -O2 -c plugin_common.c  -fPIC -DPIC -o plugin_common.lo
	(cd . && ln -fs plugin_common.lo plugin_common.o)
xoauth.lo: xoauth.c
	gcc -DHAVE_CONFIG_H -I. -I/usr/include/sasl -Wall -W -g -O2 -c xoauth.c  -fPIC -DPIC -o xoauth.lo
	(cd . && ln -fs xoauth.lo xoauth.o)
xoauth_init.lo: xoauth_init.c
	gcc -DHAVE_CONFIG_H -I. -I/usr/include/sasl -Wall -W -g -O2 -c xoauth_init.c  -fPIC -DPIC -o xoauth_init.lo
	(cd . && ln -fs xoauth_init.lo xoauth_init.o)
libxoauth.so.2.0.22: xoauth.lo xoauth_init.lo plugin_common.lo
	gcc -shared  xoauth.lo xoauth_init.lo plugin_common.lo  -lcrypt -lresolv -lc  -Wl,-soname -Wl,libxoauth.so.2 -o libxoauth.so.2.0.22
	(cd . && ln -fs libxoauth.so.2.0.22 libxoauth.so)

install: all
	install libxoauth.so.2.0.22 /usr/lib/sasl2/
	install libxoauth.so /usr/lib/sasl2/
clean:
	rm *.lo *.so.2.0.22 *.o
