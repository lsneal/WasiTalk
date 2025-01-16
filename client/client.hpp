#ifndef SERVER_H
#define SERVER_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <netinet/in.h>
#include <unordered_map>
#include <string>
#include <iostream>
#include <unistd.h>


class   Client {
    
    public:
        Client(const std::string& server_ip, int server_port);
        ~Client();

    private:
        int         _clientFd;
        int         _serverPort;
        std::string _serverIp;
        SSL_CTX*    _ctx;
        SSL*        _ssl;

};

#endif