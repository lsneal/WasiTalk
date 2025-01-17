#include "server.hpp"
#include <mutex>

int createServerSocket(int port) {

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
        std::cout << "Socket: " << clientSocket << std::endl;
        std::cout << "Client connected with IP: " << inet_ntoa(clientAddress.sin_addr) << std::endl;
        
        std::thread clientThread(WaitingClientConnection, std::ref(Server), clientSocket);
        clientThread.detach();
        
        //close(clientSocket);
    }
}

void InitOpenSSL() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_SSL_strings();
}

int main(int argc, char **argv) 
{
    int     port = atoi(argv[1]);
    Server  Server(port);

    InitOpenSSL();
    const SSL_METHOD    *method = TLS_server_method();
    //SSL_CTX             *ctx = SSL_CTX_new(method);
    Server.SetMethodSSL(context);
    //if (!ctx)
    //    return 1

    // load cert and privatekey
    if (Server.LoadCertAndPrivateKey() == -1)
        return 1
    /*if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        std::cerr << "Error load cert or private key" << std::endl;
        return 1
    }*/

    /*  INIT TCP SOCKET */
    int serverSocket = createServerSocket(port);

    SSL* ssl = AcceptSSLConnection(server_sock, ctx);

    std::thread StartServerThread(StartServer, serverSocket, Server);
    StartServerThread.join();

    close(serverSocket);

    return 0;
}