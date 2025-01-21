#include "client.hpp"

void InitOpenSSL() 
{
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
}

int main(int argc, char **argv)
{

    if (argc != 3)
        return 1;
    Client  Client(argv[1], atoi(argv[2]));

    InitOpenSSL();
    const SSL_METHOD *method = SSLv23_client_method();
    Client.SetMethodSSL(method);

    std::cout << "IP: " << Client.GetServerIp() << std::endl;
    std::cout << "Port: " << Client.GetServerPort() << std::endl;


    if (Client.connectToServer() == false) {
        std::cerr << "Error server connection" << std::endl;
        return 1;
    }

    Client.CommunicateWithServer();
    return 0;

}