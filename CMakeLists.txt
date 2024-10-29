cmake_minimum_required(VERSION 3.14)
    
# here we specify that the project is C language only, so the default
# C compiler on the system will be used
project(odc C CXX)


set(SOURCE src/main.c)
set(LIBRARIES 
    src/types.h
    src/banknote_blocks.h 
    src/banknote.h
    src/common.h src/common.c 
    src/tests.c
)

add_library(LIBS STATIC ${LIBRARIES})

add_executable(odc ${SOURCE}) 

find_package(OpenSSL REQUIRED)
target_link_libraries(odc LIBS OpenSSL::SSL m)



#include(FetchContent)
#FetchContent_Declare(
#  googletest
#  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
#)

#FetchContent_MakeAvailable(googletest)
#enable_testing()

#include_directories(src)
#set(SOURCE_TEST src/test_sha512.cpp)

#add_executable(tests ${SOURCE_TEST})
#target_link_libraries(tests LIBS GTest::gtest_main OpenSSL::SSL)

#include(GoogleTest) 
#gtest_discover_tests(tests)