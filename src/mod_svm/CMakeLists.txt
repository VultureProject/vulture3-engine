cmake_minimum_required(VERSION 2.8)
project(mod_svm)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/lib")
set(CMAKE_SHARED_LIBRARY_PREFIX "")
set(CMAKE_SHARED_LIBRARY_OUTPUT_NAME "")

#set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS_RELEASE "-Ofast -march=native")
set(CMAKE_CXX_FLAGS_RELEASE "-Ofast -march=native")
set(LIB_LINK_FLAGS "-lm -lstdc++ -flto -lhiredis")

if(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    message(STATUS "FreeBSD detected")
    include_directories(/usr/include/apr-1 /usr/local/include/apr-1/ /usr/local/include/apache24)
    set(STOP_APACHE_CMD sudo service apache24 stop)
    set(START_APACHE_CMD sudo service apache24 start)
    #set(START_APACHE_CMD httpd ... -k start)
    set(AP_MODS_DIR /usr/local/libexec/apache24/)
else()
    message(STATUS "Linux detected")
    include_directories(/usr/include/apache2 /usr/include/apr-1.0 /usr/include /usr/local/include/)
    set(STOP_APACHE_CMD sudo systemctl stop apache2)
    set(START_APACHE_CMD sudo systemctl start apache2)
    set(AP_MODS_DIR /usr/lib/apache2/modules)

    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/liblibsvm-skl.a")
        message(STATUS "Found liblibsvm-skl.a")
    else()
        message(STATUS "Download sklearnn")
        execute_process(COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/getsklearn.sh
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
    endif()
endif()

set(svm_list svm2 svm3 svm4 svm5 svm6)
foreach(svm ${svm_list})
    message(STATUS "Building mod_${svm} configuration")
    add_library(mod_${svm} SHARED mod_${svm}.c libsvm/libsvm_helper.c svm_util.c)
    set_target_properties(mod_${svm} PROPERTIES LINKER_LANGUAGE CXX)
    target_link_libraries(mod_${svm} ${LIB_LINK_FLAGS} ${CMAKE_CURRENT_SOURCE_DIR}/liblibsvm-skl.a)
    add_custom_command(
            TARGET mod_${svm}
            POST_BUILD
            COMMAND ${STOP_APACHE_CMD}
            COMMAND cp ${CMAKE_CURRENT_SOURCE_DIR}/lib/mod_${svm}.so ${AP_MODS_DIR}
            COMMAND echo "LoadModule ${svm}_module /usr/lib/apache2/modules/mod_${svm}.so" | sudo tee /etc/apache2/mods-available/${svm}.load
            COMMAND sudo a2enmod ${svm}
            COMMAND ${START_APACHE_CMD})
endforeach()