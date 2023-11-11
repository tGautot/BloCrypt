cmake_minimum_required( VERSION 3.1 )

project( BloCrypt )

set( CMAKE_CXX_STANDARD 17 )

set( GCC_COVERAGE_COMPILE_FLAGS "-Wwrite-strings" )
set(CMAKE_BUILD_TYPE Debug)   

option(WITH_TESTS "Includes tests into compilation (requires Boost library)" OFF)

if(WITH_TESTS)
    set(Boost_USE_STATIC_LIBS OFF) 
    set(Boost_USE_MULTITHREADED ON)  
    set(Boost_USE_STATIC_RUNTIME OFF) 
    find_package(Boost 1.74.0 COMPONENTS system filesystem unit_test_framework REQUIRED) 

    if(Boost_FOUND)
        include_directories(${Boost_INCLUDE_DIRS}) 
        FILE(GLOB AllTests tests/*.cpp)
        FILE(GLOB_RECURSE AllCPPSources src/*.cpp)
        list(REMOVE_ITEM AllCPPSources ${PROJECT_SOURCE_DIR}/src/main.cpp)
        add_executable( BloTests WIN32 ${AllCPPSources} ${AllTests} )
        target_include_directories( BloTests PUBLIC ./include  )
        target_link_libraries(BloTests ${Boost_FILESYSTEM_LIBRARY}
                                       ${Boost_SYSTEM_LIBRARY}
                                       ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})
    endif()
    
endif()
unset(WITH_TESTS CACHE)


FILE(GLOB_RECURSE AllCPPSources src/*.cpp)
add_executable( BloCrypt WIN32 ${AllCPPSources} )
target_include_directories( BloCrypt PUBLIC ./include  )