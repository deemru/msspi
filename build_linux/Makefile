all: static static-capix

static: libmsspi.a

static-capix: libmsspi-capix.a

shared: libmsspi.so

msspi.o:
	g++ -Wall -Wl,--no-as-needed -std=c++11 -g -O2 -fPIC -Werror -Wno-unused-function -I../third_party/cprocsp/include ../src/msspi.cpp -c -o msspi.o

msspi-capix.o:
	g++ -Wall -Wl,--no-as-needed -std=c++11 -g -O2 -fPIC -Werror -Wno-unused-function -I../third_party/cprocsp/include -DMSSPI_USE_CAPIX ../src/msspi.cpp -c -o msspi-capix.o

libmsspi.a: msspi.o
	ar cr libmsspi.a msspi.o

libmsspi-capix.a: msspi-capix.o
	ar cr libmsspi-capix.a msspi-capix.o

libmsspi.so: msspi.o
	g++ -shared -o libmsspi.so msspi.o

clean:
	rm -f libmsspi.so libmsspi.a libmsspi-capix.a msspi.o
