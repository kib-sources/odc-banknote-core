add_executable(test_crypto test_crypto.c)
find_package(OpenSSL REQUIRED)
target_link_libraries(test_crypto LIBS unity OpenSSL::SSL m)


add_executable(test_common test_common.c)
find_package(OpenSSL REQUIRED)
target_link_libraries(test_common LIBS unity OpenSSL::SSL m)

add_test(test_a test_crypto)
add_test(test_b test_common)