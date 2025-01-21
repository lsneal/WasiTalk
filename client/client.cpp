#include "client.hpp"

bool Client::connectToServer() 
{
    // Créer un socket
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

    std::cout << "OKKKKKKKKK" << _serverIp << ":" << _serverPort << std::endl;
    return true;
}

void Client::CommunicateWithServer()
{
    std::string user_input;
    char        buffer[1024];

    memset((char *)buffer, 0, sizeof(buffer));
    int bytes_read = SSL_read(this->_ssl, buffer, sizeof(buffer) - 1);
    std::cout << buffer << std::endl;

    std::getline(std::cin, user_input);
    std::cout << "'" << user_input << "'" << std::endl;
    SSL_write(this->_ssl, user_input.c_str(), user_input.length());

    memset((char *)buffer, 0, sizeof(buffer));
    bytes_read = SSL_read(this->_ssl, buffer, sizeof(buffer) - 1);
    std::cout << buffer << std::endl;

    std::getline(std::cin, user_input);
    SSL_write(this->_ssl, user_input.c_str(), user_input.length());

    while (true) 
    {
        memset((char *)buffer, 0, sizeof(buffer));
        std::getline(std::cin, user_input);

        std::cout << "USERMSG -->  " << user_input << std::endl;

        SSL_write(this->_ssl, user_input.c_str(), user_input.length());

        std::cout << "fpd" << std::endl;
        //memset((char *)buffer, 0, sizeof(buffer));
        bytes_read = SSL_read(this->_ssl, buffer, sizeof(buffer) - 1);
        std::cout << bytes_read << std::endl;
        if (bytes_read > 0) {
            buffer[bytes_read - 1] = 0;
            std::cout << "serveur: " << buffer << std::endl;
        } 
        else {
            std::cout << "ERROR" << std::endl;
            break;
        }

        memset((char *)buffer, 0, sizeof(buffer));
        std::getline(std::cin, user_input);

        std::cout << "USERMSG -->  " << user_input << std::endl;

        SSL_write(this->_ssl, user_input.c_str(), user_input.length());
    }
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