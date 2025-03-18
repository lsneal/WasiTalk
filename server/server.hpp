#ifndef SERVER_HPP
#define SERVER_HPP

#include "info.hpp"
#include "room.hpp"
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
#include <iomanip>
#include <map>

#define CERT_FILE "server_cert.pem"
#define KEY_SSL "private_key.pem"

#define ERROR_MSG(msg) std::cerr << "Error: " << msg << std::endl;
#define SERVER_LISTEN(port) std::cout << "Server listen on port: " << port << std::endl;
#define NEW_CLIENT(address, socket) std::cout << "New client connected: " << address << "with -> " << socket << std::endl;
#define CLIENT_DISCONNECTED(clientSocket) std::cout << "Client " << clientSocket << " disconnected" << std::endl;
#define INPUT_PSEUDO "Enter your pseudo: "
#define INPUT_CHATROOM "Enter chatroom name: "
#define PSEUDO_USED "Pseudo exist"

#define CREATE_COMMAND "create"
#define JOIN_COMMAND "join"
#define LIST_COMMAND "list"
#define LEAVE_COMMAND "leave"
#define NEW_RSA_COMMAND "newrsa"

enum Command {
    CREATE = 1,
    JOIN = 2,
    LIST = 3,
    LEAVE = 4,
    NEW_RSA = 5,
    INVALID
};

class   Server {
    
    public:
        Server(int port): _port(port) {}
        ~Server() {
            if (this->_ctx)
                SSL_CTX_free(this->_ctx);
            if (this->_ssl)
                SSL_free(this->_ssl);
        }

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
        SSL         *GetSessionSSLWithReadFD(fd_set read_fds);
        std::string GetUserWithSSL(SSL *ssl);
        std::string GetClientWithFd(int fd);
        std::string GetPEMwithSSL(SSL *ssl);

        void        ReceiveRSAKey(SSL *ssl, int indexClient);


        // V2 
        void        StartServer(int serverSocket);
        void        ManageClientConnected(fd_set &read_fds, fd_set &copy_fds, SSL *ssl); 

        void        Menu(Command cmd, SSL *ssl);
            
            void    CreateChatRoom(SSL *ssl);
            void    ListChatRoom(SSL *ssl);
            void    JoinChatRoom(SSL *ssl);

    private:
        std::vector<Info>   client;
        int                 _serverFd;
        int                 _port;
        SSL_CTX             *_ctx; // for certificat SSL/TLS
        SSL                 *_ssl;
        SSL                 *_tempSSL;
        std::vector<Room>   _chatroom;

};

void    WaitingClientConnection(Server &Server, int clientSocket, SSL *ssl);
void    InitOpenSSL();

bool    CheckBytesRead(int bytes_read, std::string message) ;

// MENU
Command GetCommand(std::string command);

#endif