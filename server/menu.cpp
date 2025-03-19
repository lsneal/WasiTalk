#include "server.hpp"

Command GetCommand(std::string command) 
{
    if (command == CREATE_COMMAND) return CREATE;
    if (command == JOIN_COMMAND) return JOIN;
    if (command == LIST_COMMAND) return LIST;
    if (command == LEAVE_COMMAND) return LEAVE;
    if (command == NEW_RSA_COMMAND) return NEW_RSA;
    if (command == SEND_MSG) return SEND;
    return INVALID;
}

void    Server::CreateChatRoom(SSL *ssl) 
{
    std::vector<char> room_name(1024);

    SSL_write(ssl, INPUT_CHATROOM, strlen(INPUT_CHATROOM));
    int bytesRead = SSL_read(ssl, room_name.data(), room_name.size() - 1);
    
    // CHECK BYTE READ <= 0
    room_name[bytesRead - 1] = '\0';
    
    // CHECK IF CHANNEL IS OKEY
    this->_chatroom.push_back(Room(room_name.data(), GetUserWithSSL(ssl)));
}

// list client connected
void    Server::ListChatRoom(SSL *ssl) 
{
    std::cout << "client_size: " << this->client.size() << std::endl;
    for (int i = 0; i < (int)this->client.size(); i++) {
        //SSL_write(ssl, this->_chatroom[i].GetName().c_str(), this->_chatroom[i].GetName().size());
        SSL_write(ssl, this->client[i].getPseudo().c_str(), this->client[i].getPseudo().length());
    }
}

void    Server::JoinChatRoom(SSL *ssl) 
{
    // for the moment limit to two user for key management

    std::vector<char> room_name(1024);

    SSL_write(ssl, INPUT_CHATROOM, strlen(INPUT_CHATROOM));
    int bytesRead = SSL_read(ssl, room_name.data(), room_name.size() - 1);
    
    // CHECK BYTE READ <= 0
    room_name[bytesRead - 1] = '\0';
    
    // CHECK IF CHANNEL IS OKEY
    this->_chatroom.push_back(Room(room_name.data(), GetUserWithSSL(ssl)));
}

// Send message -> <dest_user> <message>

void    Server::SendMessage(SSL *ssl, std::string user, std::string msg) 
{
    std::cout << "SEND MESSAGE FUNCTION" << std::endl;

    //int bytesRead = SSL_read(ssl, username.data(), username.size() - 1);
    //username[bytesRead - 1] = '\0';
    
    // CHECK USER

    
    SSL *ssl_send = GetSessionSSL(user);
    std::string final_msg = GetUserWithSSL(ssl) + ": " + msg;
    SSL_write(ssl_send, final_msg.c_str(), final_msg.length());



    // IF USER IF OK --> generate AES --> server send public RSA
    // encrypt and send AES
    // get pem with pseudo not with ssl object !!!!

    /*SSL *ssl_send = GetSessionSSL(username.data());
    std::string pem = GetPEMwithSSL(ssl_send);
    SSL_write(ssl, pem.c_str(), pem.length());*/

    // client encrypt msg with key
    //std::string test2 = "Enter your message: "
    //SSL_write(ssl, test2.c_str(), test2.length());

    //int bytesRead = SSL_read(ssl, username.data(), username.size() - 1);
    // MESSAGE ENCRYPT 

    //SSL_write(ssl_send, test.c_str(), test.length());

}

void    Server::Menu(Command cmd, SSL *ssl, std::string msg) 
{
    switch (cmd) {
        case LIST:
        ListChatRoom(ssl);
            break ;
        case INVALID:
        default:
            std::cerr << "Invalid command received!" << std::endl;
            break;
    }
    /*switch (cmd) {
        case CREATE:
            CreateChatRoom(ssl);
            std::cout << "Creating a new chat room..." << std::endl;
            break;
        case JOIN:
            JoinChatRoom(ssl);
            std::cout << "Joining a chat room..." << std::endl;
            break;
        case LIST:
            ListChatRoom(ssl);
            std::cout << "Listing available chat rooms..." << std::endl;
            break;
        case LEAVE:
            std::cout << "Leaving the chat room..." << std::endl;
            break;
        case NEW_RSA:
            std::cout << "Generating a new RSA key pair..." << std::endl;
            break;
        case SEND:
            SendMessage(ssl);
            break ;
        case INVALID:
        default:
            std::cerr << "Invalid command received!" << std::endl;
            break;
    }*/
}