#ifndef INFO_H
#define INFO_H

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

class Info {

    public:
        Info() {}
        ~Info() {}

    private:
        int         _fd;
        SSL         *_sslSession;
        std::string _pseudo;
        std::string _pem_key;

};

#endif