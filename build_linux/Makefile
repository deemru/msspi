all: static

static: libmsspi.a

shared: libmsspi.so

msspi.o:
	g++ -Wall -Wl,--no-as-needed -std=c++11 -g -O2 -fPIC -Werror -Wno-unused-function -I../third_party/cprocsp/include ../src/msspi.cpp -c -o msspi.o

libmsspi.a: msspi.o
	ar cr libmsspi.a msspi.o

libmsspi.so: msspi.o
	g++ -shared -o libmsspi.so msspi.o

clean:
	rm -f libmsspi.so libmsspi.a msspi.o
