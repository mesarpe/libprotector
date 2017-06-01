#include <iostream>
#include <unordered_map>
#include <string>
#include <string.h>

#include "hashtable.h"

MyHashTable::MyHashTable()
{
	//this->h = new std::unordered_map<std::string, std::string>();
}

MyHashTable::~MyHashTable()
{
	//delete this->h;
}

bool MyHashTable::addElement(const std::string new_name, const std::string old_name)
{
	this->h.emplace(new_name, old_name);
	return true;
}

std::string  MyHashTable::lookup(const std::string new_name)
{
	std::string old_name = this->h[new_name];
    return old_name;
}

unsigned int MyHashTable::size(void)
{
	return this->h.size();
}

/* WRAPPER FOR C */
MyTable newMyHashTable() {
	return reinterpret_cast<void*>(new MyHashTable());
}

void destroyMyHashTable(MyTable obj)
{
	delete reinterpret_cast<MyHashTable*>(obj);
}

void MyHashTable_addElement(MyTable obj, char * new_name, char * old_name)
{
	//std::cout <<"DEBUG:MyHashTable_addElement[" << new_name << "] = " << old_name << std::endl;
	reinterpret_cast<MyHashTable*>(obj)->addElement(new_name, old_name);
}

char * MyHashTable_lookup(MyTable obj, char * new_name)
{
	char *input = (char*) malloc(sizeof(char) * (strlen(new_name) /*+ 4*/ + 1));
	/*strcpy(str2, "lci:");*/
	if(input)
	{
		strcpy(input, new_name);

		// TODO: if the element does not exist, it is created!
		std::string res = reinterpret_cast<MyHashTable*>(obj)->lookup(input);
		char * char_res = (char*) malloc(sizeof(char) * (res.size() /*+ 4*/ + 1));
		strcpy(char_res, res.c_str());
		
		return char_res;
	
	}
	return NULL;
};

/*int main()
{
	MyHashTable * c = new MyHashTable();

	c->addElement("hola don pepito", "hola don jose");

	std::cout << "IP Address: " << c->lookup("hola don pepito") << std::endl;

    if (c->lookup("cesar").empty())
        std::cout << "The variable cesar is NULL\n" << std::endl;

	delete c;

	return 0;
}
*/
