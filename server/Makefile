CXX = cc
CFLAGS = -Wall -g
INCLUDE = -I/usr/local/include -I/usr/include -Iinclude 
LDFLAGS = -L/usr/local/lib -I/usr/lib
LDLIBS = -lcurl -lcrypto -lpthread `mysql_config --cflags --libs`


SOURCES = server.c
OUT = server 

all: build

build: $(SOURCES)
	$(CXX) -o $(OUT) $(INCLUDE) $(LDFLAGS) $(CFLAGS) $(SOURCES) $(LDLIBS)

clean:
	rm -rf server
