#include "server.hpp"

void relayMessage(SSL *fromSocket, SSL *toSocket, std::string from, std::string to)
{
    char        buffer[4096];
    int         bytesRead;
    std::mutex  sendMutex;

    while (true) 
    {
        memset((char*)buffer, 0, sizeof(buffer));
        bytesRead = SSL_read(fromSocket, buffer, sizeof(buffer));

        if (bytesRead < 0) {
            std::cerr << "Error: receiving message" << std::endl;
            break ;
        } 
        else if (bytesRead == 0) {
           //    close(fromSocket);
           // close(toSocket); 
            return ;
        }
        else {
            std::cout << "Received message: " << buffer << std::endl;
            std::lock_guard<std::mutex> lock(sendMutex);
            std::string format = from + ": " + std::string(buffer);
            SSL_write(toSocket, format.c_str(), strlen(format.c_str()));
        }
    }
    
    //close(fromSocket);
    //close(toSocket);
}

void WaitingClientConnection(Server &Server, int clientSocket, SSL *ssl) 
{
    char buffer[1024];
    int bytesRead = 0;
    
    Server.SendConnectionMessage(clientSocket, ssl);
    memset((char *)buffer, 0, sizeof(buffer));
    bytesRead = SSL_read(ssl, buffer, sizeof(buffer));

    std::string leave_msg = "Client leave: " + std::string(buffer);
    if (bytesRead == 0) {
        //Server.SendAll(leave_msg);
        Server.RemoveClient(std::string(buffer));
        //close(clientSocket);
        //return ;
    }

    if (Server.PseudoIsOkey(buffer) == true)
        Server.SetClient(clientSocket, (std::string)buffer, ssl);

    if (Server.client.size() != 1) 
    {
        Server.SendClientList(std::string(buffer), clientSocket, ssl);
    
        memset((char *)buffer, 0, sizeof(buffer));
        bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    
        if (bytesRead == 0) {
            //Server.SendAll(leave_msg);
            Server.RemoveClient(std::string(buffer));
        }
            
        SSL *ssl_session = Server.GetSessionSSL(std::string(buffer));
        
        std::thread relayThread1(relayMessage, ssl, ssl_session, \
                                    Server.GetUserWithSSL(ssl), Server.GetUserWithSSL(ssl_session));
        std::thread relayThread2(relayMessage, ssl_session, ssl, \
                                    Server.GetUserWithSSL(ssl_session), Server.GetUserWithSSL(ssl));
    
        relayThread1.detach();
        relayThread2.detach();
    }
}