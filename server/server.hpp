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

#define CERT_FILE "path"
#define KEY_SSL "path"

class   Server {
    
    public:
        Server(int port): _port(port) {}
        ~Server() {}

        int getPort() { return this->_port; }

        std::vector<Info>   client;

        void    SendConnectionMessage(int clientSocket);
        void    SendAll(std::string leave_msg);
        void    RemoveClient(std::string pseudo);
        void    SendClientList(std::string pseudo, int clientSocket);
        void    SetClient(int clientSocket, std::string pseudo);
        bool    PseudoIsOkey(std::string pseudo);
        int     GetSessionFd(std::string pseudo);

        void    SetMethodSSL(const SSL_METHOD *method) { this->_ctx = SSL_CTX_new(method); };
        int    LoadCertAndPrivateKey() {
            if (SSL_CTX_use_certificate_file(this->_ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 || 
                SSL_CTX_use_PrivateKey_file(this->_ctx, KEY_SSL, SSL_FILETYPE_PEM) <= 0) {
                            std::cerr << "Error load cert or private key" << std::endl;
                            return -1
                }
                return 1
        };
    private:
        int                 _serverFd;
        int                 _port;
        SSL_CTX*            _ctx; // for certificat SSL/TLS

};

void    WaitingClientConnection(Server &Server, int clientSocket);


/*      serverUtils        */


#endif