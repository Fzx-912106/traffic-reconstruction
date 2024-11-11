# 需求cmake最低版本
cmake_minimum_required(VERSION 3.20)
# 项目名称，版本，使用的语言
project(pcap_sniffer VERSION 0.1 LANGUAGES C)
# 设置C标准
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)
# 设置compile_commands.json生成
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
# 查找libpcap库
find_package(PkgConfig REQUIRED) #确保系统上安装了 pkg-config 工具。
pkg_check_modules(PCAP REQUIRED libpcap) #通过 pkg-config 查找 libpcap 库。

# 包含头文件路径
include_directories(${PCAP_INCLUDE_DIRS})
include_directories(include)

#添加可执行文件
add_executable(pcap_sniffer src/main.c src/packet_sniffer.c)

#链接libpcap库
target_link_libraries(pcap_sniffer ${PCAP_LIBRARIES}) #将 libpcap 库链接到可执行文件。

#编译选项
target_compile_options(pcap_sniffer PRIVATE ${PCAP_CFLAGS_OTHER}) #相当于-lpcap



