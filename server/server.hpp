#ifndef SERVER_H
#define SERVER_H

#include "info.hpp"
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

class   Server {
    
    public:
        Server(int port): _port(port) {}
        ~Server() {}

        int getPort() { return _port; }

        std::vector<Info>   client;
    private:
        int                 _serverFd;
        int                 _port;
        SSL_CTX*            _ctx; 
};

void    WaitingClientConnection(std::vector<Info> *client, int clientSocket, Info InfoClientc);

#endif