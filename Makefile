OPTIONS =-std=c++11 -g -fpermissive -Wall
LIBRARIES = -I /usr/include/openssl/ -lcrypto

all: prime kms_server kms_client servicetime_encrypt

library: src/ccn.o src/kms.o src/utils.o src/hashtable.o
	g++ $(OPTIONS) $(LIBRARIES) -shared -fPIC -o build/libprotector.so src/ccn.cc src/utils.cc src/user.cc src/kms.cc src/hashtable.cc
	

prime: src/prime.cc src/ccn.cc src/utils.cc src/user.cc
	g++ $(OPTIONS) $(LIBRARIES) -o build/prime src/prime.cc src/user.cc src/utils.cc src/ccn.cc src/kms.cc src/hashtable.cc

servicetime_encrypt: src/ccn.cc src/utils.cc src/user.cc
	g++ $(OPTIONS) $(LIBRARIES) -o build/servicetime_encrypt src/tools/servicetime_encrypt.cc src/user.cc src/utils.cc src/ccn.cc src/kms.cc src/hashtable.cc

src/utils.o: src/utils.cc src/user.cc
	g++ $(OPTIONS) -c src/utils.cc

src/hashtable.o: src/hashtable.cc
	g++ $(OPTIONS) -c src/hashtable.cc

kms_client: src/kms_client.cc src/kms.cc src/utils.cc
	g++ $(OPTIONS) $(LIBRARIES) -o build/kms_client src/kms_client.cc src/utils.cc src/user.cc

kms_server: src/kms_server.cc src/kms.cc src/utils.cc src/hashtable.cc
	g++ $(OPTIONS) -L/usr/lib/x86_64-linux-gnu/ $(LIBRARIES) -lboost_system -o build/kms_server src/kms_server.cc src/kms.cc src/hashtable.cc
src/ccn.o: src/ccn.cc
	g++ $(OPTIONS) -c src/ccn.cc

src/User.o: src/User.cc
	g++ $(OPTIONS) -c src/User.cc

src/kms.o: src/kms.cc
	g++ $(OPTIONS) -c src/kms.cc

clean:
	rm src/*.o kms_server kms_client
