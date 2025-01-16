#include "server.hpp"

bool    pseudoIsOkey(std::vector<Info> *client, std::string pseudo) 
{
    if (client->size() == 0) {
        return true;
    }

    for (int i = 0; i < client->size(); i++) {
        if ((*client)[i].getPseudo() == pseudo)
            return false;
    }
    return true;
}

void    SetClient(std::vector<Info> *client, int clientSocket, std::string pseudo, Info InfoClient) 
{
    InfoClient.setFd(clientSocket);
    //InfoClient.setPemKey()
    //InfoClient.setSSL();
    InfoClient.setPseudo(pseudo);
    client->push_back(InfoClient);
}

void    WaitingClientConnection(std::vector<Info> *client, int clientSocket, Info InfoClient) 
{

    char buffer[4096];
    int bytesRead = 0;
    std::string connection_msg = "Enter your pseudo: ";

    send(clientSocket, connection_msg.c_str(), strlen(connection_msg.c_str()), 0);
    //InfoClient.setFd(clientSocket);
    
    memset((char*)buffer, 0, sizeof(buffer));
    bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

    if (pseudoIsOkey(client, buffer) == true)
        SetClient(client, clientSocket, (std::string)buffer, InfoClient);

    // list client coonnected
    if (client->size() != 1) {
        for (int i = 0; i < client->size(); i++) {
            std::string connected = (*client)[i].getPseudo();
            send(clientSocket, connected.c_str(), strlen(connected.c_str()), 0);
        }
        std::string com = "With what client ?\n";
        send(clientSocket, com.c_str(), strlen(com.c_str()), 0);

        memset((char*)buffer, 0, sizeof(buffer));
        bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

        int session_fd = 0;
        for (int i = 0; i < client->size(); i++) {
            if ((*client)[i].getPseudo() == buffer) {
                session_fd = (*client)[i].getFd();
                break ; 
            }
        }
        memset((char*)buffer, 0, sizeof(buffer));
        bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

        send(session_fd, buffer, sizeof(buffer) - 1, 0);
    }
    // lui demander de choisir un user avec lequel communiquer
    // et ensuite recup socket pseudo 
    /*while (true) 
    {
        memset((char*)buffer, 0, sizeof(buffer));
        bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

        if (bytesRead < 0)
            std::cerr << "Error: receiving message" << std::endl;
        else
            std::cout << "Received message: " << buffer << std::endl;

        const char* response = "Message received!";
        send(clientSocket, response, strlen(response), 0);
    }*/
}