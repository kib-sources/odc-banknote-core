project("ODC" C)  
cmake_minimum_required(VERSION 3.14)
# Let's tell it a bit about our environment 
# We declare a variable to select what to build 
# Modules that exist in both our release and our unit tests, are added now   
add_subdirectory(src)  
include(CTest)
add_subdirectory(unity)
add_subdirectory(test)