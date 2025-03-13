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
        ERROR_MSG("bind socket");
        close(serverSocket);
        return -1;
    }

    if (listen(serverSocket, 5) < 0) {
        ERROR_MSG("listen socket");
        close(serverSocket);
        return -1;
    }
    SERVER_LISTEN(port);

    return serverSocket;
}

int main(int argc, char **argv) 
{
    if (argc != 2) {
        ERROR_MSG("ERROR: ./server <port>");
        return 1;
    }

    int     port = atoi(argv[1]);
    Server  Server(port);

    InitOpenSSL();
    const SSL_METHOD    *method = SSLv23_server_method();
    if (method == nullptr) {
        ERROR_MSG("UNABLE TO CREATE SSL METHOD");
        return 1;
    }
    Server.SetMethodSSL(method);

    // load cert and privatekey
    if (Server.LoadCertAndPrivateKey() == -1) {
        ERROR_MSG("ERROR LOADING CERTIFICAT")
        return 1;
    }

    /*  INIT TCP SOCKET */
    int serverSocket = createServerSocket(port);

    Server.StartServer(serverSocket);

    close(serverSocket);

    SSL_CTX_free(Server.GetContextSSL());
    EVP_cleanup();

    return 0;
}