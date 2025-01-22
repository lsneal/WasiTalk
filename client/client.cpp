#include "client.hpp"

bool Client::connectToServer() 
{
    int _clientFd = socket(AF_INET, SOCK_STREAM, 0);
    if (_clientFd == -1) {
        std::cerr << "Erreur socket creation" << std::endl;
        return false;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(_serverPort);
    if (inet_pton(AF_INET, _serverIp.c_str(), &serverAddr.sin_addr) <= 0) {
        std::cerr << "Ip invalid" << std::endl;
        return false;
    }

    if (connect(_clientFd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Error connection server" << std::endl;
        return false;
    }

    this->_ssl = SSL_new(this->_ctx);
    if (!this->_ssl) {
        std::cerr << "Error obj ssl" << std::endl;
        return false;
    }

    SSL_set_fd(this->_ssl, _clientFd);
    if (SSL_connect(this->_ssl) != 1) {
        std::cerr << "Error ssl connect" << std::endl;
        return false;
    }

    std::cout << "Connected: " << _serverIp << ":" << _serverPort << std::endl;
    return true;
}

std::mutex sendMutex;

void    ReceivMsg(SSL* _ssl)
{
    char        buffer[1024];
    int         bytes_read = 0;
    while (true) 
    {
        bytes_read = SSL_read(_ssl, buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) 
        {
            std::lock_guard<std::mutex> lock(sendMutex);
            buffer[bytes_read] = 0;
            std::cout << buffer << std::endl;
        } 
        else
        {
            std::cout << "ERROR" << std::endl;
            return ;
        }
    }
}

void    SendMsg(SSL* _ssl)
{
    std::string user_input;
    
    while (true) 
    {
        std::getline(std::cin, user_input);
        std::lock_guard<std::mutex> lock(sendMutex);
        SSL_write(_ssl, user_input.c_str(), user_input.length());
    }
}

void Client::CommunicateWithServer()
{
    std::string user_input;
    char        buffer[1024];

    memset((char *)buffer, 0, sizeof(buffer));
    //OPENSSL_cleanse(buffer, sizeof(buffer));
    int bytes_read = SSL_read(this->_ssl, buffer, sizeof(buffer) - 1);
    // function for check bytes_read

    std::getline(std::cin, user_input);
    SSL_write(this->_ssl, user_input.c_str(), user_input.length());

    SSL_write(this->_ssl, this->_publicKey.c_str(), this->_publicKey.length());

    memset((char *)buffer, 0, sizeof(buffer));
    bytes_read = SSL_read(this->_ssl, buffer, sizeof(buffer) - 1);
    std::cout << buffer << std::endl;

    std::getline(std::cin, user_input);
    SSL_write(this->_ssl, user_input.c_str(), user_input.length());

    std::thread ReceivMsgThread1(ReceivMsg, this->_ssl);
    std::thread SendMsgThread1(SendMsg, this->_ssl);

    ReceivMsgThread1.join();
    SendMsgThread1.join();
    
}