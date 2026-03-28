#include <iostream>
#include <thread>
#include <memory>
#include <signal.h>
#include "QoS.hpp"
#include "SocketWrapper.hpp"
#include "SOCKS5.hpp"

// Konfiguracja
const int PORT = 1080;
const long long GLOBAL_SPEED_LIMIT = 2 * 1024 * 1024; // 2 MB/s


void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Nie można utworzyć kontekstu SSL");
        exit(EXIT_FAILURE);
    }
    // Wymuszenie TLS 1.3 (RFC 8446)
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    return ctx;
}

void configure_context(SSL_CTX* ctx) {
    // Ścieżki do certyfikatów (muszą istnieć!)
    if (SSL_CTX_use_certificate_file(ctx, "certs/server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "certs/server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int main() {
    // Ignoruj błędy zapisu do zerwanych rur (SIGPIPE)
    signal(SIGPIPE, SIG_IGN);

    init_openssl();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

    // Utwórz globalny menedżer QoS (współdzielony przez wszystkich)
    auto global_qos = std::make_shared<QoSManager>(GLOBAL_SPEED_LIMIT);

    // Setup Socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Błąd bind");
        return 1;
    }

    listen(server_fd, 100);

    std::cout << ">>> Secure SOCKS5 Proxy (TLS 1.3) uruchomione na porcie " << PORT << std::endl;
    std::cout << ">>> QoS Limit: " << GLOBAL_SPEED_LIMIT / 1024 << " KB/s" << std::endl;

    while (true) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &len);

        if (client_fd < 0) {
            perror("Błąd accept");
            continue;
        }

        // Każdy klient w osobnym wątku
        std::thread([client_fd, ctx, global_qos]() {
            // 1. Warstwa TLS
            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, client_fd);

            if (SSL_accept(ssl) <= 0) {
                // Handshake TLS nieudany (np. klient nie używa szyfrowania)
                ERR_print_errors_fp(stderr);
                SSL_free(ssl);
                close(client_fd);
            } else {
                // 2. Warstwa SOCKS5 z włączonym QoS
                auto transport = std::make_unique<TlsTransport>(ssl, client_fd);
                Socks5Handler handler(global_qos);
                handler.handle_connection(std::move(transport));
            }
        }).detach();
    }

    close(server_fd);
    SSL_CTX_free(ctx);
    return 0;
}
