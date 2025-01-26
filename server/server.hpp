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
#include <openssl/rand.h>
#include <openssl/aes.h>

#define CERT_FILE "server_cert.pem"
#define KEY_SSL "private_key.pem"

class   Server {
    
    public:
        Server(int port): _port(port) {}
        ~Server() {}

        void        SendConnectionMessage(SSL *ssl);
        void        SendAll(std::string leave_msg);
        void        SendClientList(std::string pseudo, SSL *ssl);
        void        RemoveClient(std::string pseudo);
        bool        PseudoIsOkey(std::string pseudo);

        void        SetClient(int clientSocket, std::string pseudo, SSL *ssl);
        void        SetMethodSSL(const SSL_METHOD *method);
        int         LoadCertAndPrivateKey();

        int         GetSessionFd(std::string pseudo);
        int         GetPort() { return this->_port; }
        int         GetIndexClient(int socketClient);
        int         GetClientSize() { return this->client.size();}
        SSL_CTX     *GetContextSSL() { return this->_ctx; }
        SSL         *GetSessionSSL(std::string pseudo);
        std::string GetUserWithSSL(SSL *ssl);
        std::string GetClientWithFd(int fd);
        std::string GetPEMwithSSL(SSL *ssl);

        void        ReceiveRSAKey(SSL *ssl, int indexClient);

        /*   AES file   */
        void        sendAESKeyForSession(SSL *ssl, SSL *ssl_session);


    private:
        std::vector<Info>   client;
        int                 _serverFd;
        int                 _port;
        SSL_CTX             *_ctx; // for certificat SSL/TLS
        SSL                 *_ssl;

};

void    WaitingClientConnection(Server &Server, int clientSocket, SSL *ssl);
void    InitOpenSSL();

bool    CheckBytesRead(int bytes_read, std::string message) ;
void    generateAESKeyAndIV(std::vector<unsigned char> &key, std::vector<unsigned char> &iv);
std::string EncryptMessagesWithRSA(std::string PEM, std::vector<unsigned char> message);
#endif