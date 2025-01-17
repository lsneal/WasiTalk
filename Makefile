# Variables
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra
SSLFLAGS = -lssl -lcrypto
SERVER_DIR = server
CLIENT_DIR = client
SERVER_SRC = $(wildcard $(SERVER_DIR)/*.cpp)
CLIENT_SRC = $(wildcard $(CLIENT_DIR)/*.cpp)
SERVER_OBJ = $(SERVER_SRC:.cpp=.o)
CLIENT_OBJ = $(CLIENT_SRC:.cpp=.o)
SERVER_EXEC = server_ex
CLIENT_EXEC = client_ex
CERT_SCRIPT = gen_cert.sh

all: server client

server: $(SERVER_OBJ)
	$(CXX) $(CXXFLAGS) $(SSLFLAGS) -o $(SERVER_EXEC) $(SERVER_OBJ)

client: $(CLIENT_OBJ)
	$(CXX) $(CXXFLAGS) $(SSLFLAGS) -o $(CLIENT_EXEC) $(CLIENT_OBJ)

cert:
	./$(CERT_SCRIPT)

clean:
	rm -f $(SERVER_OBJ) $(CLIENT_OBJ)

$(SERVER_DIR)/%.o: $(SERVER_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(CLIENT_DIR)/%.o: $(CLIENT_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

fclean: clean
	rm -f $(SERVER_EXEC) $(CLIENT_EXEC)

.PHONY: all server client cert clean fclean
