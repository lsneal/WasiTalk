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
    std::vector<char>   buffer(4096);
    int                 bytes_read = 0;

    while (true) 
    {
        bytes_read = SSL_read(_ssl, buffer.data(), buffer.size());
        if (bytes_read > 0) 
        {
            std::lock_guard<std::mutex> lock(sendMutex);
            std::cout << buffer.data() << std::endl;
            OPENSSL_cleanse(buffer.data(), buffer.size());
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
        OPENSSL_cleanse(&user_input[0], user_input.size());
    }
}

bool     CheckBytesRead(int bytes_read, std::string message) 
{
    if (bytes_read > 0)
        std::cout << message << std::endl;
    else if (bytes_read == 0) 
    {
        std::cerr << "Connection close" << std::endl;
        return false;
    }
    else
    {
        std::cerr << "Error read messages" << std::endl;
        return false;
    }
    return true;
}


int    Client::StartCommunicationWithServer(std::vector<char> buffer) 
{
    std::string         user_input;

    // Receive server message for pseudo
    buffer.assign(buffer.size(), 0);
    int bytes_read = SSL_read(this->_ssl, buffer.data(), buffer.size());
    
    if (CheckBytesRead(bytes_read, buffer.data()) == false)
        return -1;
    
    // Write pseudo
    std::getline(std::cin, user_input);
    SSL_write(this->_ssl, user_input.c_str(), user_input.length());

    // Send publickey RSA
    buffer.assign(buffer.size(), 0);
    SSL_write(this->_ssl, this->_publicKey.c_str(), this->_publicKey.length() - 1);

    // Read server message pseudo list
    buffer.assign(buffer.size(), 0);
    bytes_read = SSL_read(this->_ssl, buffer.data(), buffer.size());

    if (CheckBytesRead(bytes_read, buffer.data()) == false)
        return -1;

    // Enter pseudo list for communicate or send code for solo user
    std::string serv = "Solo on server";
    if (serv.compare(buffer.data()) != 0) 
    {
        std::cout << "RECEIVE RSA" << std::endl;
        std::getline(std::cin, user_input);
        SSL_write(this->_ssl, user_input.c_str(), user_input.length());
    
        // generate aes and iv
        std::string aes = "aes key";

        // receive rsa key
        bytes_read = SSL_read(this->_ssl, buffer.data(), buffer.size());
        if (CheckBytesRead(bytes_read, buffer.data()) == false)
            return -1;

        std::cout << "RSA: " << buffer.data() << std::endl;
        // encrypt aes and iv with rsa
        // send message at server 
        return 1;
    }
    std::cout << "YOOOOO" << std::endl;
    SSL_write(this->_ssl, this->_publicKey.c_str(), this->_publicKey.length());
    return 1;
}

int    Client::InitCommunicationWithRSA(std::vector<char> buffer) 
{
    buffer.assign(buffer.size(), 0);
    
    int bytes_read = SSL_read(this->_ssl, buffer.data(), buffer.size());
    //if (CheckBytesRead(bytes_read, buffer.data()) == false)
    //    return -1;
    
    std::string ivkey = buffer.data();

    std::cout << "Key: " << "'" << ivkey << "'" << std::endl;
    
    // receive AES key
    // decrypt message with privateKey
    // save AES key
    return 0 ;
}

void Client::CommunicateWithServer()
{
    std::vector<char>   buffer(1024);

    //OPENSSL_cleanse(buffer, sizeof(buffer));
    if (StartCommunicationWithServer(buffer) == -1)
        return ;

//    if (InitCommunicationWithRSA(buffer) == -1)
//        return ;

    std::thread ReceivMsgThread1(ReceivMsg, this->_ssl);
    std::thread SendMsgThread1(SendMsg, this->_ssl);

    ReceivMsgThread1.join();
    SendMsgThread1.join();
    
}