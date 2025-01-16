#include "server.hpp"


int main(int argc, char **argv) 
{

    int port = 9999;
    Server Server(port);

    std::cout << Server.getPort() << std::endl;

    return 0;
}