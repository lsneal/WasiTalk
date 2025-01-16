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


class   Server {
    
    public:
        Server(int port);
        ~Server();

    private:
        int         server_fd;
        int         port;
        SSL_CTX*    ctx; 
        std::unordered_map<int, SSL *> client_ssl; // fd + SSL connection /* faire classe client */
        std::unordered_map<int, std::string pseudo> client_id; // fd + pseudo
        std::unordered_map<int, EVP_PKEY *> client_id; // fd + public_key

};

#endif