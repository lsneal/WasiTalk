#include "server.hpp"
#include <mutex>

int createServerSocket(int port) 
{

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

void    Server::StartServer(int serverSocket)
{
    sockaddr_in clientAddress;
    socklen_t clientAddressLen = sizeof(clientAddress);
    fd_set read_fds;
    
    // init fd
    FD_ZERO(&read_fds);
    FD_SET(serverSocket, &read_fds);
    int max_fd = serverSocket;

    while (true) 
    {
        fd_set copy_fds = read_fds;
        int activity = select(max_fd + 1, &copy_fds, nullptr, nullptr, nullptr);

        if (activity < 0) {
            std::cerr << "Error: select failed" << std::endl;
            break ;
        }

        // if new client
        if (FD_ISSET(serverSocket, &copy_fds)) 
        {
            int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddress, &clientAddressLen);
            if (clientSocket < 0) {
                std::cerr << "Error: accept failed" << std::endl;
                continue ;
            }

            // config ssl new client
            SSL* ssl = SSL_new(this->_ctx);
            SSL_set_fd(ssl, clientSocket);
            if (SSL_accept(ssl) == -1) 
            {
                std::cerr << "Error SSL accept" << std::endl;
                close(clientSocket);
                SSL_free(ssl);
                continue ;
            }

            // PSEUDO CLIENT and check if exist
            char buf[1024];

            while (1)
            {
                std::string yupseudo = "Enter your pseudo: ";
                SSL_write(ssl, yupseudo.c_str(), yupseudo.length());
                int bytesRead = SSL_read(ssl, buf, sizeof(buf) - 1);
                
                if (PseudoIsOkey(buf) == true) {
                    break ;
                }
                std::string error = "Pseudo exist";
                SSL_write(ssl, error.c_str(), error.length());
            }

            
            // add fd new client
            FD_SET(clientSocket, &read_fds);
            max_fd = std::max(max_fd, clientSocket);
            this->client.push_back(Info(clientSocket, buf, ssl));

            std::cout << "New client connected: " << inet_ntoa(clientAddress.sin_addr) << " with socket: " << clientSocket << std::endl;
        }

        // client connected
        ManageClientConnected(read_fds, copy_fds);

    }
}

void    Server::ManageClientConnected(fd_set &read_fds, fd_set &copy_fds) 
{
    for (int i = 0; i < GetClientSize(); i++) 
    {
        int clientSocket = this->client[i].getFd();
        if (FD_ISSET(clientSocket, &copy_fds)) 
        {
            char buffer[1024];
            int bytesRead = SSL_read(GetSessionSSL("pseudo"), buffer, sizeof(buffer) - 1);
            if (bytesRead <= 0)
            {
                // deconnection client
                if (bytesRead == 0) {
                    std::cout << "Client " << clientSocket << " disconnected." << std::endl;
                } else {
                    std::cerr << "Error reading from client " << clientSocket << std::endl;
                }

                // close connnection
                SSL_shutdown(GetSessionSSL("pseudo"));
                SSL_free(GetSessionSSL("pseudo"));
                close(clientSocket);
                FD_CLR(clientSocket, &read_fds);
            } 
            else
            {
                buffer[bytesRead] = '\0';
                std::cout << "Message from client " << clientSocket << ": " << buffer << std::endl;
                


                // Exemple
                /*for (const auto& pair : clientSSLs) {
                    if (pair.first != clientSocket) {
                        SSL_write(pair.second, buffer, strlen(buffer));
                    }
                }*/
            }
        }
    }
}

int main(int argc, char **argv) 
{
    if (argc != 2)
        return 1;

    std::string buffer;

    memset((char *)buffer.c_str(), 0, sizeof(buffer.c_str()));

    int     port = atoi(argv[1]);
    Server  Server(port);

    InitOpenSSL();
    const SSL_METHOD    *method = SSLv23_server_method();
    Server.SetMethodSSL(method);

    // load cert and privatekey
    if (Server.LoadCertAndPrivateKey() == -1)
        return 1;

    /*  INIT TCP SOCKET */
    int serverSocket = createServerSocket(port);

    Server.StartServer(serverSocket);

    close(serverSocket);

    SSL_CTX_free(Server.GetContextSSL());
    EVP_cleanup();

    return 0;
}