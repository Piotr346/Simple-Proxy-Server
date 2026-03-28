
#pragma once

#include <mutex>
#include <condition_variable>
#include <chrono>
#include <algorithm>
#include <iostream>

// Klasa implementująca algorytm Token Bucket
class QoSManager {
    long long tokens;           // Dostępne bajty
    const long long capacity;   // Maksymalny "burst"
    const long long rate_per_sec; // Prędkość odnawiania
    
    std::mutex mtx;
    std::condition_variable cv;
    std::chrono::steady_clock::time_point last_refill;

public:
    QoSManager(long long rate_bytes_per_sec) 
        : rate_per_sec(rate_bytes_per_sec), 
          capacity(rate_bytes_per_sec), // Burst = 1 sekunda transferu
          tokens(rate_bytes_per_sec) {
        last_refill = std::chrono::steady_clock::now();
    }

    // Blokuje wątek, dopóki nie pobierze wymaganej liczby tokenów
    void consume(long long amount) {
        if (amount <= 0) return;
        
        std::unique_lock<std::mutex> lock(mtx);
        while (true) {
            refill(); // Dolej żetony

            if (tokens >= amount) {
                tokens -= amount;
                return; // Mamy wystarczająco -> przepuszczamy
            }

            // Oblicz ile brakuje i jak długo spać
            long long needed = amount - tokens;
            double wait_seconds = (double)needed / rate_per_sec;
            
            // Czekaj
            cv.wait_for(lock, std::chrono::duration<double>(wait_seconds));
        }
    }

private:
    void refill() {
        auto now = std::chrono::steady_clock::now();
        double seconds = std::chrono::duration<double>(now - last_refill).count();
        
        long long new_tokens = (long long)(seconds * rate_per_sec);
        if (new_tokens > 0) {
            tokens = std::min(tokens + new_tokens, capacity);
            last_refill = now;
        }
    }
};
