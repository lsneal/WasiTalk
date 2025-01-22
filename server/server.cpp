#include "server.hpp"

void relayMessage(SSL *fromSocket, SSL *toSocket, std::string from, std::string to)
{
    std::vector<char>   buffer(1024);
    int                 bytesRead;
    std::mutex          sendMutex;

    while (true) 
    {
        bytesRead = SSL_read(fromSocket, buffer.data(), buffer.size());

        if (bytesRead < 0) {
            std::cerr << "Error: receiving message" << std::endl;
            break ;
        } 
        else if (bytesRead == 0) {
           // close(fromSocket);
           // close(toSocket); 
            return ;
        }
        else {
            std::cout << from << " send: " << buffer.data() << " at " << to << std::endl;
            std::lock_guard<std::mutex> lock(sendMutex);
            std::string format = from + ": " + std::string(buffer.data());
            SSL_write(toSocket, format.c_str(), strlen(format.c_str()));
        }
    }
    
    //close(fromSocket);
    //close(toSocket);
}

void WaitingClientConnection(Server &Server, int clientSocket, SSL *ssl) 
{
    std::vector<char>   buffer(1024);
    int bytesRead = 0;
    
    Server.SendConnectionMessage(ssl);
    buffer.assign(buffer.size(), 0);
    bytesRead = SSL_read(ssl, buffer.data(), buffer.size());
    
    if (CheckBytesRead(bytesRead, buffer.data()) == false)
        return ;

    std::string leave_msg = "Client leave: " + std::string(buffer.data());
    if (bytesRead == 0) {
        //Server.SendAll(leave_msg);
        Server.RemoveClient(buffer.data());
        //close(clientSocket);
        //return ;
    }

    if (Server.PseudoIsOkey(buffer.data()) == true)
        Server.SetClient(clientSocket, buffer.data(), ssl);

    Server.ReceiveRSAKey(ssl, Server.GetIndexClient(clientSocket));
    std::cout << "'" << buffer.data() << "'" << std::endl;

    if (Server.GetClientSize() != 1) 
    {
        Server.SendClientList(std::string(buffer.data()), ssl);
    
        buffer.assign(buffer.size(), 0);
        bytesRead = SSL_read(ssl, buffer.data(), buffer.size());
    
        // remove vector <Info> if client leave
        if (CheckBytesRead(bytesRead, buffer.data()) == false)
            return ;

        SSL *ssl_session = Server.GetSessionSSL(buffer.data());
        
        std::cout << "Session create with --> " << Server.GetUserWithSSL(ssl) << " and " << Server.GetUserWithSSL(ssl_session) << std::endl;

        std::thread relayThread1(relayMessage, ssl, ssl_session, \
                                    Server.GetUserWithSSL(ssl), Server.GetUserWithSSL(ssl_session));
        std::thread relayThread2(relayMessage, ssl_session, ssl, \
                                    Server.GetUserWithSSL(ssl_session), Server.GetUserWithSSL(ssl));
    
        relayThread1.detach();
        relayThread2.detach();
    }
}

bool     CheckBytesRead(int bytes_read, std::string message) 
{
    if (bytes_read > 0)
        std::cout << message << std::endl;
    else if (bytes_read == 0) 
    {
        std::cerr << "Connection close" << std::endl;
        return false;
    }
    else
    {
        std::cerr << "Error read messages" << std::endl;
        return false;
    }
    return true;
}