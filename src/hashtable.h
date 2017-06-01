#ifndef HASHTABLE_H
#define HASHTABLE_H

#ifdef __cplusplus
	#include <unordered_map>
	#include <string>
#endif


#ifdef __cplusplus
	class MyHashTable{
		
		public:
			std::unordered_map<std::string, std::string> h;
			
			MyHashTable(void);
			~MyHashTable(void);
			
			bool addElement(const std::string old_name, const std::string new_name);
			std::string lookup(const std::string);
			unsigned int size(void);
	};
#endif

typedef void * MyTable;

/* Wrapper for C */
#ifdef __cplusplus
	extern "C" {
#endif
		MyTable newMyHashTable();
		void destroyMyHashTable(MyTable obj);
		void MyHashTable_addElement(MyTable obj, char * new_name, char * old_name);
		char * MyHashTable_lookup(MyTable obj, char * new_name);
#ifdef __cplusplus
	}
#endif

// The C interface
//

#endif