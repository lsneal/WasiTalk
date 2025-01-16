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
        int         client_fd;
        int         server_port;
        std::string server_ip;
        SSL_CTX*    ctx;
        SSL*        ssl;

};

#endif