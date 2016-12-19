all: msspi.o

msspi.o:
	g++ -Wall -Wl,--no-as-needed -std=c++11 -g -O2 -Werror -Wno-unused-function -I../third_party/cprocsp/include ../src/msspi.cpp -c -o msspi.o
