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
#include <thread>
#include <mutex>

#define CERT_FILE "server_cert.pem"
#define KEY_SSL "private_key.pem"

class   Server {
    
    public:
        Server(int port): _port(port) {}
        ~Server() {}

        int         GetPort() { return this->_port; }
        SSL_CTX     *GetContextSSL() { return this->_ctx; }

        std::vector<Info>   client;

        void    SendConnectionMessage(int clientSocket);
        void    SendAll(std::string leave_msg);
        void    RemoveClient(std::string pseudo);
        void    SendClientList(std::string pseudo, int clientSocket);
        void    SetClient(int clientSocket, std::string pseudo, SSL *ssl);
        bool    PseudoIsOkey(std::string pseudo);
        int     GetSessionFd(std::string pseudo);

        void    SetMethodSSL(const SSL_METHOD *method);
        int     LoadCertAndPrivateKey();

    private:
        int                 _serverFd;
        int                 _port;
        SSL_CTX             *_ctx; // for certificat SSL/TLS
        SSL                 *_ssl;

};

void    WaitingClientConnection(Server &Server, int clientSocket, SSL *ssl);
void    InitOpenSSL();

/*      serverUtils        */


#endif