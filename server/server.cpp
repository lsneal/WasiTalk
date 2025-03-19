#include "server.hpp"

bool    AES1 = false;
bool    AES2 = false;

void relayMessage(SSL *fromSocket, SSL *toSocket, std::string from, std::string to)
{
    std::vector<char>   buffer(4096);
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
            std::string disconnected = from + " disconnected";
            SSL_write(toSocket, disconnected.c_str(), disconnected.length());
            SSL_shutdown(toSocket);
            SSL_shutdown(fromSocket);
            return ;
        }
        else {
            std::cout << from << " send: " << buffer.data() << " at " << to << std::endl;
            std::lock_guard<std::mutex> lock(sendMutex);
            std::string format = from + ": " + std::string(buffer.data());
            SSL_write(toSocket, format.c_str(), strlen(format.c_str()));
            OPENSSL_cleanse(buffer.data(), buffer.size());
        }
    }
}

void sendAESKeyToClient(SSL *ssl, const std::string &aesKey)
{
    int bytesSent = SSL_write(ssl, aesKey.c_str(), aesKey.length());
    if (bytesSent < 0) {
        std::cerr << "Error: send AES key" << std::endl;
    } 
    else {
        std::cout << "Key send" << std::endl;
        //OPENSSL_cleanse(aesKey.c_str(), aesKey.length());
    }
}

bool readFromSSL(SSL* ssl, std::vector<char>& buffer) {
    int bytesRead = SSL_read(ssl, buffer.data(), buffer.size());
    if (CheckBytesRead(bytesRead, buffer.data()) == false) {
        return false;
    }
    return true;
}

void WaitingClientConnection(Server &Server, int clientSocket, SSL *ssl) 
{
    std::vector<char>   buffer(1024);
    
    Server.SendConnectionMessage(ssl);
    buffer.assign(buffer.size(), 0);

    if (readFromSSL(ssl, buffer) == false)
        return ;

    /*std::string leave_msg = "Client leave: " + std::string(buffer.data());
    if (bytesRead == 0) {
        //Server.SendAll(leave_msg);
        Server.RemoveClient(buffer.data());
        //close(clientSocket);
        //return ;
    }*/

    /*if (Server.PseudoIsOkey(buffer.data()) == true)
        Server.SetClient(clientSocket, buffer.data(), ssl);*/

    Server.ReceiveRSAKey(ssl, Server.GetIndexClient(clientSocket));

    if (Server.GetClientSize() > 1) 
    {
        bool session = false;

        while (!session)
        {

            Server.SendClientList(std::string(buffer.data()), ssl);
    
            buffer.assign(buffer.size(), 0);

            if (readFromSSL(ssl, buffer) == false)
                return ;
            
            SSL *ssl_session = Server.GetSessionSSL(buffer.data());
            if (ssl_session != nullptr)
            {
                session = true;
                std::cout << "Session create with --> " << Server.GetUserWithSSL(ssl) << " and " << Server.GetUserWithSSL(ssl_session) << std::endl;

                std::thread relayThread1(relayMessage, ssl, ssl_session, \
                                            Server.GetUserWithSSL(ssl), Server.GetUserWithSSL(ssl_session));
                std::thread relayThread2(relayMessage, ssl_session, ssl, \
                                            Server.GetUserWithSSL(ssl_session), Server.GetUserWithSSL(ssl));
                
                relayThread1.detach();
                relayThread2.detach();
            }
            else 
                std::cout << "User not found" << std::endl;
        }
    }
    else 
    {
        std::string message = "Solo on server";
        SSL_write(ssl, message.c_str(), strlen(message.c_str()));
    }
}