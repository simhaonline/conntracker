GLIB_INCLUDES += `pkg-config --cflags glib-2.0`
GLIB_LIBS += `pkg-config --libs glib-2.0`
CONNTRACK_LIBS += `pkg-config --libs libnetfilter_conntrack`

all:
	gcc -I. $(GLIB_INCLUDES) -Wall -O2 -g -ggdb -o conntracker conntracker.c $(GLIB_LIBS) $(CONNTRACK_LIBS)

clean:
	rm -f conntracker
