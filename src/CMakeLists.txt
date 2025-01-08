set(SOURCE main.c)
set(LIBRARIES 
    types.h
    banknote_blocks.h 
    banknote.h
    common.h common.c 
)

add_library(LIBS STATIC ${LIBRARIES})

add_executable(odc ${SOURCE}) 

find_package(OpenSSL REQUIRED)
target_link_libraries(odc LIBS OpenSSL::SSL m uuid)


target_include_directories(odc PUBLIC ${UUID_INCLUDE_DIRS})
target_include_directories(odc PUBLIC ${CMAKE_CURRENT_LIST_DIR})
target_include_directories(LIBS PUBLIC ${CMAKE_CURRENT_LIST_DIR})