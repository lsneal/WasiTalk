#include "server.hpp"

std::mutex clients_mutex; 

bool    Server::PseudoIsOkey(std::string pseudo) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    if ((int)this->client.size() == 0) {
        return true;
    }

    for (int i = 0; i < (int)this->client.size(); i++) {
        if (this->client[i].getPseudo() == pseudo)
            return false;
    }
    return true;
}

void    Server::SetClient(int clientSocket, std::string pseudo, SSL *ssl) 
{
    Info newClient(clientSocket, pseudo, ssl);
    this->client.push_back(newClient);
}

// modif with SSL
void    Server::SendAll(std::string leave_msg)
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (int i = 0; i < (int)this->client.size(); i++) {
        send(this->client[i].getFd(), leave_msg.c_str(), strlen(leave_msg.c_str()), 0);
    }
}

void    Server::SendConnectionMessage(SSL *ssl) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    std::string connection_msg = "Enter your pseudo: ";
    SSL_write(ssl, connection_msg.c_str(), strlen(connection_msg.c_str()));
}

void    Server::SendClientList(std::string pseudo, SSL *ssl) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (int i = 0; i < (int)this->client.size(); i++) 
    {
        if (client[i].getPseudo() != pseudo) {
            std::string connected = this->client[i].getPseudo();
            SSL_write(ssl, connected.c_str(), strlen(connected.c_str()));
        }
    }
}

int    Server::GetSessionFd(std::string pseudo) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (int i = 0; i < (int)this->client.size(); i++) 
    {
        if (this->client[i].getPseudo() == pseudo)
            return this->client[i].getFd();
    }
    return -1; 
}

std::string Server::GetClientWithFd(int fd)
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (int i = 0; i < (int)this->client.size(); i++) 
    {
        if (this->client[i].getFd() == fd)
            return this->client[i].getPseudo();
    }
    return NULL; 
}

SSL    *Server::GetSessionSSL(std::string pseudo) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (int i = 0; i < (int)this->client.size(); i++) 
    {
        if (this->client[i].getPseudo() == pseudo)
            return this->client[i].getSSL();
    }
    return NULL; 
}

void    Server::RemoveClient(std::string pseudo) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);    
    for (int i = 0; i < (int)this->client.size(); i++) {
        if (this->client[i].getPseudo() == pseudo) { 
            this->client.erase(this->client.begin() + i);
            std::cout << "Remove size = " << this->client.size() << std::endl;
            break ;
        }
    }
}

std::string Server::GetUserWithSSL(SSL *ssl) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);    
    for (int i = 0; i < (int)this->client.size(); i++) {
        if (this->client[i].getSSL() == ssl) { 
            return this->client[i].getPseudo();
        }
    }
    return NULL;
}

int         Server::GetIndexClient(int socketClient) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);    
    for (int i = 0; i < (int)this->client.size(); i++) {
        if (this->client[i].getFd() == socketClient) { 
            return i;
        }
    }
    return -1;
}

void    Server::ReceiveRSAKey(SSL *ssl, int indexClient) 
{
    char buffer[4096];
    memset((char *)buffer, 0, sizeof(buffer));
    int bytesRead = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    
    this->client[indexClient].setPemKey(buffer);
    std::cout << "public:   " << this->client[indexClient].getPemKey() << std::endl;
}