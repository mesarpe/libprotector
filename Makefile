OPTIONS =-std=c++11 -g -fpermissive -Wall
LIBRARIES = -I /usr/include/openssl/ -lcrypto

all: prime kms_server kms_client servicetime_encrypt

library: src/lib/ccn.o src/lib/kms.o src/lib/utils.o src/lib/hashtable.o
	g++ $(OPTIONS) $(LIBRARIES) -shared -fPIC -o build/libprotector.so src/lib/ccn.cc src/lib/utils.cc src/lib/user.cc src/lib/kms.cc src/lib/hashtable.cc
	

prime: src/tools/prime.cc src/lib/ccn.cc src/lib/utils.cc src/lib/user.cc
	g++ $(OPTIONS) $(LIBRARIES) -o build/prime src/tools/prime.cc src/lib/user.cc src/lib/utils.cc src/lib/ccn.cc src/lib/kms.cc src/lib/hashtable.cc

servicetime_encrypt: src/lib/ccn.cc src/lib/utils.cc src/lib/user.cc
	g++ $(OPTIONS) $(LIBRARIES) -o build/servicetime_encrypt src/tools/servicetime_encrypt.cc src/lib/user.cc src/lib/utils.cc src/lib/ccn.cc src/lib/kms.cc src/lib/hashtable.cc

src/lib/utils.o: src/lib/utils.o src/lib/user.o
	g++ $(OPTIONS) -c src/lib/utils.cc

src/lib/hashtable.o: src/lib/hashtable.cc
	g++ $(OPTIONS) -c src/lib/hashtable.cc

kms_client: src/tools/kms_client.cc src/lib/kms.o src/lib/utils.o
	g++ $(OPTIONS) $(LIBRARIES) -o build/kms_client src/tools/kms_client.cc src/lib/utils.cc src/lib/user.cc

kms_server: src/tools/kms_server.cc src/lib/kms.cc src/lib/utils.cc src/lib/hashtable.cc
	g++ $(OPTIONS) -L/usr/lib/x86_64-linux-gnu/ $(LIBRARIES) -lboost_system -o build/kms_server src/tools/kms_server.cc src/lib/kms.cc src/lib/hashtable.cc
src/lib/ccn.o: src/ccn.cc
	g++ $(OPTIONS) -c src/lib/ccn.cc

src/lib/user.o:
	g++ $(OPTIONS) -c src/lib/user.cc

src/lib/kms.o: src/lib/kms.cc
	g++ $(OPTIONS) -c src/lib/kms.cc

clean:
	rm src/*.o kms_server kms_client
