#pragma once

#include "SocketWrapper.hpp"
#include "QoS.hpp"
#include <thread>
#include <vector>
#include <cstring>
#include <arpa/inet.h>
#include <netdb.h>

class Socks5Handler {
    std::shared_ptr<QoSManager> qos; // Współdzielony licznik QoS

public:
    Socks5Handler(std::shared_ptr<QoSManager> qos_ref) : qos(qos_ref) {}

    // Główna funkcja obsługi klienta
    void handle_connection(std::unique_ptr<ITransport> client) {
        char buf[512];

        // --- KROK 1: Greeting (RFC 1928) ---
        // Klient wysyła wersję i metody autoryzacji
        if (client->read(buf, 2) != 2 || buf[0] != 0x05) return;
        
        int nmethods = buf[1];
        client->read(buf, nmethods); // Pobierz metody (ignorujemy w tym demo, zakładamy No Auth)

        // Odpowiedź: Ver 5, Method 0 (No Authentication)
        char greeting[] = {0x05, 0x00};
        client->write(greeting, 2);

        // --- KROK 2: Request ---
        // Format: VER CMD RSV ATYP DST.ADDR DST.PORT
        if (client->read(buf, 4) != 4) return;
        
        if (buf[1] != 0x01) { // Obsługujemy tylko CONNECT (0x01)
            std::cerr << "Nieobsługiwana komenda SOCKS: " << (int)buf[1] << std::endl;
            return; 
        }

        struct sockaddr_in target_addr = {0};
        target_addr.sin_family = AF_INET;
        char atyp = buf[3];

        if (atyp == 0x01) { // IPv4
            client->read((char*)&target_addr.sin_addr, 4);
            client->read((char*)&target_addr.sin_port, 2);
        } else if (atyp == 0x03) { // Domena
            char len;
            client->read(&len, 1);
            char domain[256];
            client->read(domain, len);
            domain[(int)len] = 0;
            
            client->read((char*)&target_addr.sin_port, 2);
            
            // DNS Lookup
            struct hostent* host = gethostbyname(domain);
            if (!host) return;
            memcpy(&target_addr.sin_addr, host->h_addr, host->h_length);
        } else {
            return; // IPv6 (0x04) pominięte dla czytelności
        }

        // --- KROK 3: Connect to Target ---
        int target_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(target_fd, (struct sockaddr*)&target_addr, sizeof(target_addr)) < 0) {
            return; // Błąd połączenia
        }
        
        // Owijamy surowy socket w obiekt Transportu
        auto target = std::make_unique<TcpTransport>(target_fd);

        // Odpowiedź sukces dla klienta
        char resp[] = {0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0};
        client->write(resp, 10);

        // --- KROK 4: Relay Data (Wielowątkowo) ---
        relay(std::move(client), std::move(target));
    }

private:
    void relay(std::unique_ptr<ITransport> client, std::unique_ptr<ITransport> target) {
        // Używamy surowych wskaźników wewnątrz lambdy, bo unique_ptr nie jest kopiowalny
        ITransport* c_ptr = client.get();
        ITransport* t_ptr = target.get();
        
        bool active = true;

        // Wątek 1: Upload (Klient -> Internet) - Zazwyczaj bez limitu QoS
        std::thread uploader([&]() {
            char buffer[8192];
            while (active) {
                int bytes = c_ptr->read(buffer, sizeof(buffer));
                if (bytes <= 0) { active = false; break; }
                t_ptr->write(buffer, bytes);
            }
        });

        // Wątek 2: Download (Internet -> Klient) - TU APLIKUJEMY QoS!
        char buffer[8192];
        while (active) {
            int bytes = t_ptr->read(buffer, sizeof(buffer));
            if (bytes <= 0) { active = false; break; }

            // === QoS ENFORCEMENT ===
            qos->consume(bytes); // Zablokuj, jeśli przekroczono limit
            // =======================

            c_ptr->write(buffer, bytes);
        }

        if (uploader.joinable()) uploader.join();
        // unique_ptr automatycznie zamknie połączenia przy wyjściu z funkcji
    }
};
