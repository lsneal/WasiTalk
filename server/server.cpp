#include "server.hpp"

std::mutex clients_mutex; 

bool    pseudoIsOkey(std::vector<Info> *client, std::string pseudo) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);
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
    std::lock_guard<std::mutex> lock(clients_mutex);
    InfoClient.setFd(clientSocket);
    //InfoClient.setPemKey()
    //InfoClient.setSSL();
    InfoClient.setPseudo(pseudo);
    client->push_back(InfoClient);
}

void    SendAll(std::vector<Info> *client, std::string leave_msg)
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (int i = 0; i < client->size(); i++) {
        send((*client)[i].getFd(), leave_msg.c_str(), strlen(leave_msg.c_str()), 0);
    }
}

void SendConnectionMessage(std::vector<Info> *client, int clientSocket) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    std::string connection_msg = "Enter your pseudo: ";
    send(clientSocket, connection_msg.c_str(), strlen(connection_msg.c_str()), 0);
}

void    SendClientList(std::vector<Info> *client, std::string pseudo, int clientSocket) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (int i = 0; i < client->size(); i++) {
        if ((*client)[i].getPseudo() != pseudo) {
            std::string connected = (*client)[i].getPseudo();
            send(clientSocket, connected.c_str(), strlen(connected.c_str()), 0);
        }
    }
}

int     GetSessionFd(std::vector<Info> *client, std::string pseudo) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (int i = 0; i < client->size(); i++) 
    {
        if ((*client)[i].getPseudo() == pseudo)
            return (*client)[i].getFd();
    }
    return -1; 
}

void    RemoveClient(std::vector<Info> *client, std::string pseudo) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);    
    for (int i = 0; i < client->size(); i++) {
        std::cout << "hi" << std::endl;
        if ((*client)[i].getPseudo() == pseudo) { 
            client->erase(client->begin() + i);
            std::cout << "Remove size = " << client->size() << std::endl;
            break ;
        }
    }
}

void relayMessage(std::vector<Info> *client, int fromSocket, int toSocket)
{
    char        buffer[4096];
    int         bytesRead;
    std::mutex  sendMutex;

    while (true) 
    {
        memset((char*)buffer, 0, sizeof(buffer));
        bytesRead = recv(fromSocket, buffer, sizeof(buffer) - 1, 0);

        if (bytesRead < 0) {
            std::cerr << "Error: receiving message" << std::endl;
            break ;
        } 
        else if (bytesRead == 0) {
            //RemoveClient(client, std::string(buffer));
            close(toSocket); 
            break ;
        }
        else {
            std::cout << "Received message: " << buffer << std::endl;
            std::lock_guard<std::mutex> lock(sendMutex);
            send(toSocket, buffer, bytesRead, 0);
        }
    }

    //close(fromSocket);
    //close(toSocket);
}

void WaitingClientConnection(std::vector<Info> *client, int clientSocket, Info InfoClient) 
{
    char buffer[4096];
    int bytesRead = 0;
    
    SendConnectionMessage(client, clientSocket);
    memset((char *)buffer, 0, sizeof(buffer));
    bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

    std::string leave_msg = "Client leave: " + std::string(buffer);
    if (bytesRead == 0) {
        std::cout << "size list client = " << client->size() << std::endl;
        SendAll(client, leave_msg);
        RemoveClient(client, std::string(buffer));
        //close(clientSocket);
        //return ;
    }

    if (pseudoIsOkey(client, buffer) == true)
        SetClient(client, clientSocket, (std::string)buffer, InfoClient);

    if (client->size() != 1) 
    {
        SendClientList(client, std::string(buffer), clientSocket);
    
        memset((char *)buffer, 0, sizeof(buffer));
        bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
        if (bytesRead == 0) {
            std::cout << "size list client = " << client->size() << std::endl;
            SendAll(client, leave_msg);
            RemoveClient(client, std::string(buffer));
        }
            
        int session_fd = GetSessionFd(client, std::string(buffer));
    
        std::thread relayThread1(relayMessage, client, clientSocket, session_fd);
        std::thread relayThread2(relayMessage, client, session_fd, clientSocket);
    
        relayThread1.detach();
        relayThread2.detach();
    }
}