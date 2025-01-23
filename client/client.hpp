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
#include <cstring>

class   Client {
    
    public:
        Client(const std::string& server_ip, int server_port,  \
               const std::string& publicKey, const std::string& privateKey): \
                    _serverIp(server_ip), \
                    _serverPort(server_port), \
                    _publicKey(publicKey), \
                    _privateKey(privateKey) {}
        ~Client() {}

        std::string     GetServerIp() { return this->_serverIp; }
        int             GetServerPort() { return this->_serverPort; }
        SSL_CTX         *GetContextSSL() { return this->_ctx; }

        bool            connectToServer();
        void            sendMessage(const std::string message);
        void            CommunicateWithServer();
        int             StartCommunicationWithServer(std::vector<char> buffer);
        int             InitCommunicationWithRSA(std::vector<char> buffer);
        std::string     receiveMessage();
        
        void            SetMethodSSL(const SSL_METHOD *method) { 
            this->_ctx = SSL_CTX_new(method); 

            /*  WARNING !!! Not secure for production  */
            SSL_CTX_set_verify(this->_ctx, SSL_VERIFY_NONE, NULL);
            if (!SSL_CTX_load_verify_locations(this->_ctx, "server_cert.pem", NULL)) {
                std::cerr << "Error load cert" << std::endl;
                exit(1);
            }
        };

        void    EncryptMessagesWithRSA(std::string message); 


    private:
        std::string _serverIp;
        int         _serverPort;
        std::string _publicKey;
        std::string _privateKey;
        SSL_CTX*    _ctx;
        SSL*        _ssl;
        
};

bool generateRSAKeys(std::string &publicKey, std::string &privateKey);
bool CheckBytesRead(int bytes_read, std::string message);

#endif