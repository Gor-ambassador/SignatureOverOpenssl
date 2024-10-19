cmake_minimum_required(VERSION 3.10)

# Название проекта
project(SignAndVerifyTool)

# Устанавливаем стандарт C++
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Поиск библиотеки OpenSSL
find_package(OpenSSL REQUIRED)

# Создаём исполняемый файл
add_executable(signature_tool main.cpp)

# Линкуем OpenSSL к нашему исполняемому файлу
target_link_libraries(signature_tool OpenSSL::SSL OpenSSL::Crypto)
