cmake_minimum_required(VERSION 3.2)
project(vkalloc)

add_library(vkalloc src/vkalloc.c)

target_include_directories(vkalloc
        PUBLIC
        include)