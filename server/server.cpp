#include "server.hpp"

bool    pseudoIsOkey(Server Server, std::string pseudo) 
{
    if (Server.client.size() == 0) {
        return true;
    }

    for (int i = 0; i < Server.client.size(); i++) {
        if (Server.client[i].getPseudo() == pseudo)
            return false;
    }
    return true;
}

void    SetClassClient(std::vector<Info> *client, int clientSocket, std::string pseudo, Info InfoClient) 
{
    InfoClient.setFd(clientSocket);
    //InfoClient.setPemKey()
    //InfoClient.setSSL();
    InfoClient.setPseudo(pseudo);
    client->push_back(InfoClient);
}

void    WaitingClientConnection(Server Server, int clientSocket, Info InfoClient) 
{

    char buffer[4096];
    int bytesRead = 0;
    const char  *connection_msg = "Enter your pseudo: ";

    send(clientSocket, connection_msg, strlen(connection_msg), 0);
    //InfoClient.setFd(clientSocket);
    
    memset((char*)buffer, 0, sizeof(buffer));
    bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

    std::cout << buffer << std::endl;
    // check pseudo if okey --> client send all, and set class client
    if (pseudoIsOkey(Server, buffer) == true)
        SetClassClient(&Server.client, clientSocket, (std::string)buffer, InfoClient);
    
    // send au client les user connecter
    // lui demander de choisir un user avec lequel communiquer
    // et ensuite recup socket pseudo 
    while (true) 
    {
        memset((char*)buffer, 0, sizeof(buffer));
        bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

        if (bytesRead < 0)
            std::cerr << "Error: receiving message" << std::endl;
        else
            std::cout << "Received message: " << buffer << std::endl;

        const char* response = "Message received!";
        send(clientSocket, response, strlen(response), 0);
    }
}