cmake_minimum_required( VERSION 3.1 )

project( BloCrypt )

set( CMAKE_CXX_STANDARD 17 )

include_directories( ${OPENGL_INCLUDE_DIRS} )

SET( GCC_COVERAGE_COMPILE_FLAGS "-Wwrite-strings" )
set(CMAKE_BUILD_TYPE Debug)   

add_executable( BloCrypt WIN32 src/AES.cpp src/main.cpp )
target_include_directories( BloCrypt PUBLIC ./include  )