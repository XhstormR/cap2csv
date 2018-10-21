set(APP_NAME cap2csv)

aux_source_directory(. SOURCE)

add_executable(${APP_NAME} ${SOURCE})

target_link_libraries(${APP_NAME}
        PRIVATE ${LIBRARY_VAR1}
        PRIVATE ws2_32
        )
target_include_directories(${APP_NAME}
        PRIVATE ${PCAP_INCLUDE_DIR}
        PRIVATE ${TCPDUMP_INCLUDE_DIR}
        )
#target_compile_definitions(${APP_NAME}
#        PRIVATE -DHAVE_REMOTE
#        )

install(DIRECTORY ../lib/ DESTINATION bin)
install(TARGETS ${APP_NAME} RUNTIME DESTINATION bin)
