#include "server.hpp"
#include <mutex>

int createServerSocket(int port) 
{

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddress;

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(port);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    if (bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0) {
        std::cerr << "Error: bind socket" << std::endl;
        close(serverSocket);
        return -1;
    }

    if (listen(serverSocket, 5) < 0) {
        std::cerr << "Error: listen socket" << std::endl;
        close(serverSocket);
        return -1;
    }
    std::cout << "Server listen on port: " << port << "..." << std::endl;

    return serverSocket;
}

void    StartServer(int serverSocket, Server Server)  
{
    while (true) 
    {
        sockaddr_in clientAddress;
        socklen_t clientAddressLen = sizeof(clientAddress);

        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientAddressLen);
        if (clientSocket < 0) {
            std::cerr << "Error: accept connection" << std::endl;
            continue;
        }

        SSL *ssl = SSL_new(Server.GetContextSSL());
        SSL_set_fd(ssl, clientSocket);
        if (SSL_accept(ssl) == -1) {
            std::cerr << "Error SSL acceptation" << std::endl;
            return ;
        }

        std::cout << "Socket: " << clientSocket << std::endl;
        std::cout << "Client connected with IP: " << inet_ntoa(clientAddress.sin_addr) << std::endl;

        std::thread clientThread(WaitingClientConnection, std::ref(Server), clientSocket, ssl);
        clientThread.detach();
        
        //SSL_shutdown(ssl);
        //SSL_free(ssl);
        //close(clientSocket);
    }
}


int main(int argc, char **argv) 
{
    if (argc != 2)
        return 1;

    std::string buffer;

    memset((char *)buffer.c_str(), 0, sizeof(buffer.c_str()));

    int     port = atoi(argv[1]);
    Server  Server(port);

    InitOpenSSL();
    const SSL_METHOD    *method = SSLv23_server_method();
    Server.SetMethodSSL(method);

    // load cert and privatekey
    if (Server.LoadCertAndPrivateKey() == -1)
        return 1;

    /*  INIT TCP SOCKET */
    int serverSocket = createServerSocket(port);

    std::thread StartServerThread(StartServer, serverSocket, Server);
    StartServerThread.join();


    close(serverSocket);

    SSL_CTX_free(Server.GetContextSSL());
    EVP_cleanup();

    return 0;
}