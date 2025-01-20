#include "client.hpp"

bool Client::connectToServer() 
{
    // Créer un socket
    _clientFd = socket(AF_INET, SOCK_STREAM, 0);
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

    //SSL
    this->_ssl = SSL_new(this->_ctx);
    if (!this->_ssl) {
        std::cerr << "Error obj ssl" << std::endl;
        return false;
    }

    // Associer le socket au SSL
    SSL_set_fd(this->_ssl, _clientFd);
    
    // Initier la connexion SSL
    if (SSL_connect(this->_ssl) != 1) {
        std::cerr << "error ssl connect" << std::endl;
        return false;
    }


    std::cout << "OKKKKKKKKK" << _serverIp << ":" << _serverPort << std::endl;
    return true;
}

void Client::sendMessage(const std::string message) 
{
    (void)message;
    std::cout << "send" << std::endl;
}

std::string Client::receiveMessage() 
{
    std::cout << "recv" << std::endl;
    return NULL;
}