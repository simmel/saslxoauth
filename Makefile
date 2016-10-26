CFLAGS=-Wall -Wextra -pedantic -I/usr/include/sasl -g -D_FORTIFY_SOURCE=2 -fno-strict-overflow -fstack-protector-all -fPIE --param ssp-buffer-size=1 -Wshadow -Wpointer-arith -Wconversion -Wcast-qual -Wwrite-strings -Wunreachable-code
LDFLAGS=-lsasl2

all: libxoauth.so.2.0.22
plugin_common.lo: plugin_common.c
	gcc $(CFLAGS) -DHAVE_CONFIG_H -I. -O2 -c plugin_common.c -fPIC -DPIC -o plugin_common.lo
	(cd . && ln -fs plugin_common.lo plugin_common.o)
xoauth.lo: xoauth.c
	gcc $(CFLAGS) -DHAVE_CONFIG_H -I. -O2 -c xoauth.c -fPIC -DPIC -o xoauth.lo
	(cd . && ln -fs xoauth.lo xoauth.o)
xoauth_init.lo: xoauth_init.c
	gcc $(CFLAGS) -DHAVE_CONFIG_H -I. -O2 -c xoauth_init.c -fPIC -DPIC -o xoauth_init.lo
	(cd . && ln -fs xoauth_init.lo xoauth_init.o)
libxoauth.so.2.0.22: xoauth.lo xoauth_init.lo plugin_common.lo
	gcc $(CFLAGS) -shared xoauth.lo xoauth_init.lo plugin_common.lo -loauth -lcrypt -lresolv -lc -Wl,-soname -Wl,libxoauth.so.2 -o libxoauth.so.2.0.22

install: all
	install libxoauth.so.2.0.22 /usr/lib/sasl2/
	(cd /usr/lib/sasl2/ && ln -sf libxoauth.so.2.0.22 libxoauth.so)
	(cp --no-clobber .xoauthrc.sample ~/.xoauthrc && chown $(SUDO_USER):$(SUDO_GID) ~/.xoauthrc && chmod 600 ~/.xoauthrc)
clean:
	rm -f *.lo *.so *.so.2.0.22 *.o
