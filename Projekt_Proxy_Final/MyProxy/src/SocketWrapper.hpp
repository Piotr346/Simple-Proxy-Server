
#pragma once


#include <sys/socket.h> 
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <memory>
#include <iostream>

// Interfejs abstrakcyjny (Polimorfizm)
class ITransport {
public:
    virtual ~ITransport() = default;
    virtual int read(char* buf, int size) = 0;
    virtual int write(const char* buf, int size) = 0;
    virtual void close_conn() = 0;
    virtual int get_fd() const = 0;
};

// Implementacja 1: Zwykłe TCP (do łączenia się z docelowymi serwerami)
class TcpTransport : public ITransport {
    int fd;
public:
    TcpTransport(int socket_fd) : fd(socket_fd) {}
    ~TcpTransport() { close_conn(); }

    int read(char* buf, int size) override { return ::recv(fd, buf, size, 0); }
    int write(const char* buf, int size) override { return ::send(fd, buf, size, 0); }
    
    void close_conn() override {
        if (fd != -1) { ::close(fd); fd = -1; }
    }
    int get_fd() const override { return fd; }
};

// Implementacja 2: TLS 1.3 (dla bezpiecznego połączenia z klientem)
class TlsTransport : public ITransport {
    SSL* ssl;
    int fd;
public:
    TlsTransport(SSL* ssl_ctx, int socket_fd) : ssl(ssl_ctx), fd(socket_fd) {}
    ~TlsTransport() {
        if (ssl) { 
             // SSL_shutdown(ssl); // Opcjonalnie graceful shutdown
             SSL_free(ssl); 
        }
        if (fd != -1) ::close(fd);
    }

    int read(char* buf, int size) override { 
        if (!ssl) return -1;
        return SSL_read(ssl, buf, size); 
    }
    
    int write(const char* buf, int size) override { 
        if (!ssl) return -1;
        return SSL_write(ssl, buf, size); 
    }
    
    void close_conn() override {
        // RAII zajmie się czyszczeniem
    }
    int get_fd() const override { return fd; }
};
