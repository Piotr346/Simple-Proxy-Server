
#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Konfiguracja
const std::string PROXY_IP = "127.0.0.1";
const int PROXY_PORT = 1080;
const std::string TARGET_HOST = "ifconfig.me"; // Strona testowa
const int TARGET_PORT = 80;

void cleanup(int sock, SSL* ssl, SSL_CTX* ctx) {
    if (ssl) { SSL_shutdown(ssl); SSL_free(ssl); }
    if (sock != -1) close(sock);
    if (ctx) SSL_CTX_free(ctx);
}

int main() {
    // 1. Inicjalizacja OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    // Tworzymy kontekst klienta TLS 1.3
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Błąd tworzenia kontekstu SSL" << std::endl;
        return 1;
    }

    // WAŻNE: Wyłączamy weryfikację certyfikatu (bo używamy self-signed)
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    // 2. Połączenie TCP z Proxy
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PROXY_PORT);
    inet_pton(AF_INET, PROXY_IP.c_str(), &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Nie można połączyć się z Proxy na porcie " << PROXY_PORT << std::endl;
        return 1;
    }
    std::cout << "[TCP] Połączono z Proxy." << std::endl;

    // 3. Handshake TLS (Owijamy socket w SSL)
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        cleanup(sock, ssl, ctx);
        return 1;
    }
    std::cout << "[TLS] Tunel zaszyfrowany (TLS 1.3)." << std::endl;

    // 4. SOCKS5 Handshake - Krok 1: Greeting
    // Ver: 0x05, NMethods: 1, Method: 0x00 (No Auth)
    char greeting[] = {0x05, 0x01, 0x00};
    if (SSL_write(ssl, greeting, sizeof(greeting)) <= 0) return 1;

    char buffer[4096];
    if (SSL_read(ssl, buffer, sizeof(buffer)) <= 0) return 1;

    if (buffer[0] != 0x05 || buffer[1] != 0x00) {
        std::cerr << "Błąd autoryzacji SOCKS5!" << std::endl;
        return 1;
    }

    // 5. SOCKS5 Handshake - Krok 2: Request (CONNECT)
    // Budujemy pakiet ręcznie:
    // VER | CMD | RSV | ATYP (0x03=Domain) | LEN | DOMAIN... | PORT
    std::vector<unsigned char> request;
    request.push_back(0x05); // Ver
    request.push_back(0x01); // Cmd: Connect
    request.push_back(0x00); // Rsv
    request.push_back(0x03); // Atyp: Domain Name
    request.push_back((unsigned char)TARGET_HOST.length()); // Długość domeny
    for (char c : TARGET_HOST) request.push_back(c); // Domena
    
    // Port (Network Byte Order)
    request.push_back((TARGET_PORT >> 8) & 0xFF);
    request.push_back(TARGET_PORT & 0xFF);

    SSL_write(ssl, request.data(), request.size());

    // Odbiór odpowiedzi od proxy (czy udało się połączyć z celem?)
    int len = SSL_read(ssl, buffer, sizeof(buffer));
    if (len < 10 || buffer[1] != 0x00) {
        std::cerr << "Proxy nie połączyło się z celem. Kod błędu: " << (int)buffer[1] << std::endl;
        return 1;
    }
    std::cout << "[SOCKS5] Tunel zestawiony do: " << TARGET_HOST << std::endl;

    // 6. Wysyłamy zwykłe żądanie HTTP przez tunel
    std::string http_req = "GET / HTTP/1.1\r\nHost: " + TARGET_HOST + "\r\nConnection: close\r\n\r\n";
    SSL_write(ssl, http_req.c_str(), http_req.length());

    // 7. Odczytujemy odpowiedź
    std::cout << "\n--- ODPOWIEDŹ SERWERA ---" << std::endl;
    while (true) {
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) break;
        buffer[bytes] = 0; // Null-terminator dla wypisania stringa
        std::cout << buffer;
    }
    std::cout << "\n-------------------------" << std::endl;

    cleanup(sock, ssl, ctx);
    return 0;
}
