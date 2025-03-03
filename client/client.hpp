#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <netinet/in.h>
#include <openssl/rand.h>
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
#include <iomanip>

#define AES_BLOCK_SIZE 32

class   Client {
    
    public:
        Client(const std::string& server_ip, int server_port,  \
               const std::string& publicKey, const std::string& privateKey): \
                    _serverIp(server_ip), \
                    _serverPort(server_port), \
                    _publicKey(publicKey), \
                    _privateKey(privateKey) {}
        ~Client() {
            if (this->_ctx)
                SSL_CTX_free(this->_ctx);
            if (this->_ssl)
                SSL_free(this->_ssl);
        }

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
        void    EncryptAndSendAES(std::string public_key);

        void testEncrypt(std::string PEM);

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

// AES

std::string DecryptAESWithRSA(std::string PEM, std::vector<unsigned char> encrypted);
std::string EncryptAESWithRSA(std::string PEM, std::vector<unsigned char> message);

std::vector<unsigned char>  base64_decode(const std::string& encoded_string);
std::string                 base64_encode(std::vector<unsigned char> data);
void                        convertToHex(std::vector<unsigned char>& data, std::vector<unsigned char> &hex_data);
void                        generateAESKeyAndIV(std::vector<unsigned char> &key, std::vector<unsigned char> &iv);


#endif

