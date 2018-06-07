cmake_minimum_required(VERSION 2.8)

add_executable(socksv5 main.c
                       hello.c
                       request.c
                       netutils.c
                       buffer.c
                       selector.c
                       stm.c
                       socks5nio.c)
target_link_libraries(socksv5 pthread)

if(CHECK_FOUND)
    add_executable(hello_test 
                   hello_test.c hello.c buffer.c)
    target_link_libraries(hello_test check)
    add_test(NAME hello_test COMMAND hello_test)

    add_executable(request_test
                   request_test.c request.c buffer.c)
    add_test      (NAME request_test COMMAND request_test)
    target_link_libraries(request_test check)

    add_executable(netutils_test
                   netutils_test.c netutils.c buffer.c)
    add_test      (NAME netutils_test COMMAND netutils_test)
    target_link_libraries(netutils_test check)

    add_executable(buffer_test 
                   buffer_test.c)
    add_test      (NAME buffer_test COMMAND buffer_test)
    target_link_libraries(buffer_test check)

    add_executable(selector_test 
                   selector_test.c)
    add_test      (NAME selector_test COMMAND selector_test)
    target_link_libraries(selector_test check pthread)

    add_executable(stm_test 
                   stm_test.c stm.c)
    add_test      (NAME stm_test COMMAND stm_test)
    target_link_libraries(stm_test check)
endif()
