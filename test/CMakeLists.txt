add_executable(test_crypto test_crypto.c)
find_package(OpenSSL REQUIRED)
target_link_libraries(test_crypto LIBS unity OpenSSL::SSL m uuid)


add_executable(test_common test_common.c)
find_package(OpenSSL REQUIRED)
target_link_libraries(test_common LIBS unity OpenSSL::SSL m uuid)

add_executable(test_banknote_header test_banknote_header.c)
find_package(OpenSSL REQUIRED)
target_link_libraries(test_banknote_header LIBS unity OpenSSL::SSL m uuid)

add_test(test_cryptography_functions test_crypto)
add_test(test_common_functions test_common)
add_test(test_banknote_header_functions test_banknote_header)
