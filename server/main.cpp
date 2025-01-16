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

int main(int argc, char **argv) 
{

    int     port = atoi(argv[1]);
    Server  Server(port);
    Info    Info;

    /*  INIT TCP SOCKET */
    int serverSocket = createServerSocket(port);

    while (true) {
        sockaddr_in clientAddress;
        socklen_t clientAddressLen = sizeof(clientAddress);

        int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientAddressLen);
        if (clientSocket < 0) {
            std::cerr << "Error: accept connection" << std::endl;
            continue;
        }
        std::cout << "Socket: " << clientSocket << std::endl;
        std::cout << "Client connected with IP: " << inet_ntoa(clientAddress.sin_addr) << std::endl;
        
        //WaitingClientConnection(&Server.client, clientSocket, Info);
        
        std::thread clientThread(WaitingClientConnection, &Server.client, clientSocket, Info);
        clientThread.detach();
//    close(clientSocket);


    }
    close(serverSocket);

    return 0;
}