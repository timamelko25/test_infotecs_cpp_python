cmake_minimum_required(VERSION 3.8)
project(traffic_sniffer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Добавляем исходные файлы
add_executable(traffic_sniffer 
    main.cpp 
    PcapReader.h PcapReader.cpp 
    PacketAnalyzer.h PacketAnalyzer.cpp 
    FlowStatistics.h FlowStatistics.cpp
)

# Находим библиотеку PCAP
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Подключаем заголовочные файлы и библиотеки
target_include_directories(traffic_sniffer PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(traffic_sniffer PRIVATE ${PCAP_LIBRARIES})

# Вывод отладочной информации
message(STATUS "PCAP_INCLUDE_DIRS = ${PCAP_INCLUDE_DIRS}")
message(STATUS "PCAP_LIBRARIES = ${PCAP_LIBRARIES}")
