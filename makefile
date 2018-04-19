all:test
test:server.c team3.h
	gcc -o server server.c -pthread `mysql_config --cflags --libs` -lcrypto


