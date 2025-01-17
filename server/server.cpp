#include "server.hpp"

void relayMessage(int fromSocket, int toSocket)
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
            close(fromSocket);
            close(toSocket); 
            return ;
        }
        else {
            std::cout << "Received message: " << buffer << std::endl;
            std::lock_guard<std::mutex> lock(sendMutex);
            send(toSocket, buffer, bytesRead, 0);
        }
    }
    
    close(fromSocket);
    close(toSocket);
}


void WaitingClientConnection(Server &Server, int clientSocket, SSL *ssl) 
{
    char buffer[4096];
    int bytesRead = 0;
    
    Server.SendConnectionMessage(clientSocket);
    memset((char *)buffer, 0, sizeof(buffer));
    //bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    bytesRead = SSL_read(ssl, buffer, sizeof(buffer));

    std::string leave_msg = "Client leave: " + std::string(buffer);
    if (bytesRead == 0) {
        Server.SendAll(leave_msg);
        Server.RemoveClient(std::string(buffer));
        //close(clientSocket);
        //return ;
    }

    /*if (Server.PseudoIsOkey(buffer) == true)
        Server.SetClient(clientSocket, (std::string)buffer, ssl);

    if (Server.client.size() != 1) 
    {
        Server.SendClientList(std::string(buffer), clientSocket);
    
        memset((char *)buffer, 0, sizeof(buffer));
        bytesRead = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
        if (bytesRead == 0) {
            Server.SendAll(leave_msg);
            Server.RemoveClient(std::string(buffer));
        }
            
        int session_fd = Server.GetSessionFd(std::string(buffer));
    
        std::thread relayThread1(relayMessage, clientSocket, session_fd);
        std::thread relayThread2(relayMessage, session_fd, clientSocket);
    
        relayThread1.detach();
        relayThread2.detach();
    }*/
}