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
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <thread>
#include <mutex>

class   Client {
    
    public:
        Client(const std::string& server_ip, int server_port): _serverIp(server_ip), _serverPort(server_port) {}
        ~Client() {}

        std::string GetServerIp() { return this->_serverIp; }
        int         GetServerPort() { return this->_serverPort; }
        SSL_CTX     *GetContextSSL() { return this->_ctx; }

        bool connectToServer();
        void sendMessage(const std::string message);
        std::string receiveMessage();
        void    SetMethodSSL(const SSL_METHOD *method) { 
            this->_ctx = SSL_CTX_new(method); 
            SSL_CTX_set_verify(this->_ctx, SSL_VERIFY_NONE, NULL);
        };

    private:
        std::string _serverIp;
        SSL_CTX*    _ctx;
        SSL*        _ssl;
        int         _serverPort;
        int         _clientFd;

};

#endif