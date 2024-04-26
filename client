#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fstream> // for file operations

#define PORT 8080
#define SERVER_IP "127.0.0.1"

// Caesar cipher encryption function
std::string encryptCaesarCipher(const std::string& message, int shift) {
    std::string encryptedMessage = "";
    for (char character : message) {
        if (isalpha(character)) {
            char shiftedChar = character + shift;
            if (isupper(character) && shiftedChar > 'Z') {
                shiftedChar = 'A' + (shiftedChar - 'Z' - 1);
            } else if (islower(character) && shiftedChar > 'z') {
                shiftedChar = 'a' + (shiftedChar - 'z' - 1);
            }
            encryptedMessage += shiftedChar;
        } else {
            encryptedMessage += character; // Keep non-alphabetic characters unchanged
        }
    }
    return encryptedMessage;
}

// Function to authenticate user
bool authenticateUser(const std::string& username, const std::string& password) {
    if (username == "Omar" && password == "biba123") {
        return true;
    }
    return false;
}

// Function to save username and password to a file
void saveCredentialsToFile(const std::string& username, const std::string& password) {
    std::ofstream credentialsFile("credentials.txt", std::ios::app);
    if (credentialsFile.is_open()) {
        credentialsFile << "Username: " << username << ", Password: " << password << std::endl;
        credentialsFile.close();
    } else {
        std::cout << "Failed to open credentials file." << std::endl;
    }
}

int main() {
    int clientSocket;
    struct sockaddr_in serverAddr;
    char buffer[1024] = {0};

    // Create a socket
    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Initialize server address structure
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(SERVER_IP);
    serverAddr.sin_port = htons(PORT);

    // Connect to the server
    if (connect(clientSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "Connected to server!" << std::endl;

    // Prompt user for username and password
    std::string username, password;
    std::cout << "Enter username: ";
    std::getline(std::cin, username);
    std::cout << "Enter password: ";
    std::getline(std::cin, password);

    // Save username and password to file
    saveCredentialsToFile(username, password);

    // Authenticate user
    if (!authenticateUser(username, password)) {
        std::cout << "Invalid username or password. Authentication failed." << std::endl;
        exit(EXIT_FAILURE);
    }

    while (true) {
        // Get user input
        std::string message;
        std::cout << "You: ";
        std::getline(std::cin, message);

        // Send the message to server
        send(clientSocket, message.c_str(), message.length(), 0);

        // Receive reply from server
        int bytesReceived = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesReceived <= 0) {
            perror("Receive failed");
            exit(EXIT_FAILURE);
        }

        std::cout << "Server: " << buffer << std::endl;
    }

    close(clientSocket);
    return 0;
}
