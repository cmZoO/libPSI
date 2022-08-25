
#project(fronend)


 

#############################################
#               Build fronend.exe           #
#############################################

file(GLOB_RECURSE SRC_CMPT ${CMAKE_SOURCE_DIR}/cmpt/*.cpp)
include_directories(${CMAKE_SOURCE_DIR}/cmpt/)

add_executable(cmpt.exe ${SRC_CMPT})


#############################################
#            Link our libraries             #
#############################################



#############################################
#                 Link libOTe               #
#############################################

target_link_libraries(cmpt.exe PUBLIC libPSI libPSI_Tests oc::libOTe_Tests oc::tests_cryptoTools)
