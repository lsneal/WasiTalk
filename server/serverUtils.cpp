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
    std::lock_guard<std::mutex> lock(clients_mutex);
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
    return nullptr; 
}

SSL    *Server::GetSessionSSLWithReadFD(fd_set read_fds) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (int i = 0; i < (int)this->client.size(); i++) 
    {
        if (this->client[i].getReadFd() == read_fds)
            return this->client[i].getSSL();
    }
    return nullptr; 
}

void    Server::RemoveClient(std::string pseudo) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);    
    for (int i = 0; i < (int)this->client.size(); i++) 
    {
        if (this->client[i].getPseudo() == pseudo) { 
            this->client.erase(this->client.begin() + i);
            break ;
        }
    }
}

std::string Server::GetUserWithSSL(SSL *ssl) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);    
    for (int i = 0; i < (int)this->client.size(); i++)
    {
        if (this->client[i].getSSL() == ssl) { 
            return this->client[i].getPseudo();
        }
    }
    return NULL;
}

int         Server::GetIndexClient(int socketClient) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);    
    for (int i = 0; i < (int)this->client.size(); i++)
    {
        if (this->client[i].getFd() == socketClient) { 
            return i;
        }
    }
    return -1;
}

void    Server::ReceiveRSAKey(SSL *ssl, int indexClient) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);  
    std::vector<char>           buffer(4096);  
    int                         bytesRead = SSL_read(ssl, buffer.data(), buffer.size());
    (void)bytesRead;
    //if (CheckBytesRead(bytesRead, buffer.data()) == false)
    //    return ;

    //std::cout << indexClient << std::endl;
    this->client[indexClient].setPemKey(buffer.data());
    //std::cout << "PEM: " << std::endl;
    //std::cout << "'" << this->client[indexClient].getPemKey() << "'" << std::endl;
}

std::string Server::GetPEMwithSSL(SSL *ssl) 
{
    std::lock_guard<std::mutex> lock(clients_mutex);    
    for (int i = 0; i < (int)this->client.size(); i++)
    {
        if (this->client[i].getSSL() == ssl) { 
            return this->client[i].getPemKey();
        }
    }
    return NULL;
}

bool     CheckBytesRead(int bytes_read, std::string message) 
{
    if (bytes_read > 0)
        std::cout << message << std::endl;
    else if (bytes_read == 0) 
    {
        ERROR_MSG("CONNECTION CLOSE");
        return false;
    }
    else
    {
        ERROR_MSG("ERROR READ MESSAGE");
        return false;
    }
    return true;
}