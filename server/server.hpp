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

        std::vector<Info>   client;

        void    SendConnectionMessage(SSL *ssl);
        void    SendAll(std::string leave_msg);
        void    SendClientList(std::string pseudo, int clientSocket, SSL *ssl);
        void    RemoveClient(std::string pseudo);
        bool    PseudoIsOkey(std::string pseudo);

        void    SetClient(int clientSocket, std::string pseudo, SSL *ssl);
        void    SetMethodSSL(const SSL_METHOD *method);
        int     LoadCertAndPrivateKey();

        int         GetSessionFd(std::string pseudo);
        int         GetPort() { return this->_port; }
        SSL_CTX     *GetContextSSL() { return this->_ctx; }
        SSL         *GetSessionSSL(std::string pseudo);
        std::string GetUserWithSSL(SSL *ssl);

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