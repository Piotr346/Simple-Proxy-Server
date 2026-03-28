
cmake_minimum_required(VERSION 3.10)
project(SecureSocks5Proxy)

# Wymagany standard C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Znajdź bibliotekę OpenSSL (wymagana do TLS 1.3)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Pliki źródłowe
add_executable(proxy 
    src/main.cpp
    # Reszta to pliki nagłówkowe (.hpp), więc nie trzeba ich tu wymieniać, 
    # kompilator sam je dołączy przez #include w main.cpp.
)

# Dołączanie nagłówków
target_include_directories(proxy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

# Linkowanie bibliotek (OpenSSL + Wątki)
target_link_libraries(proxy OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
