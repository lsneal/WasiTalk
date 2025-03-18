#ifndef ROOM_HPP
#define ROOM_HPP

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <netinet/in.h>
#include <unordered_map>
#include <string>
#include <iostream>
#include <unistd.h>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <mutex>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <iomanip>
#include <map>

class   Room {
    
    public:
        Room(std::string name, std::string creator) {
            this->_name = name;
            this->_listUsername.push_back(creator);
        }
        ~Room() {}

        std::string GetName() { return this->_name; }

    private:
        std::string                 _name;
        std::vector<std::string>    _listUsername;

};

#endif