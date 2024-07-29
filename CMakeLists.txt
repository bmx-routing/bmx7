cmake_minimum_required (VERSION 3.18.0)
project(bmx7)


find_package(Git REQUIRED)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

#list(APPEND BMX7_SOURCES
set(BMX7_SOURCES
	src/allocate.c
	src/avl.c
	src/bmx.c
	src/content.c
	src/control.c
	src/crypt.c
	src/desc.c
	src/dump.c
	src/hna.c
	src/iid.c
	src/ip.c
	src/iptools.c
	src/key.c
	src/link.c
	src/list.c
	src/metrics.c
	src/msg.c
	src/node.c
	src/ogm.c
	src/plugin.c
	src/prof.c
	src/redist.c
	src/schedule.c
	src/sec.c
	src/tools.c
	src/z.c
)

add_executable(${PROJECT_NAME} ${BMX7_SOURCES})
target_include_directories(${PROJECT_NAME} PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_compile_definitions(${PROJECT_NAME} PRIVATE AVL_5XLINKED )

find_library(mbedtls_library mbedtls)
find_library(mbedcrypto_library mbedcrypto)
target_link_libraries(${PROJECT_NAME} PRIVATE ${mbedtls_library} ${mbedcrypto_library} m z iw)

set_target_properties(
        ${PROJECT_NAME}
          PROPERTIES
            COMPILE_WARNING_AS_ERROR YES
            C_STANDARD 99
            C_STANDARD_REQUIRED YES
#            C_EXTENSIONS YES
)

# TODO: Look for corresponding target properties instead of hardcoding compiler
# flags @see set_target_properties
target_compile_options(${PROJECT_NAME} PRIVATE -pedantic -W -Wall -Wstrict-prototypes -Wno-unused-parameter -Wno-address-of-packed-member -Os -g3)

# target_compile_options(PRIVATE -pedantic -W -Wall -Wstrict-prototypes -Wno-unused-parameter -Wno-address-of-packed-member -Os -g3)


include_directories(PRIVATE src)

add_library(common INTERFACE)
target_compile_options(common INTERFACE -pedantic -W -Wall -Wstrict-prototypes -Wno-unused-parameter -Wno-address-of-packed-member -Os -g3)
target_compile_definitions(common INTERFACE AVL_5XLINKED )

set(BMX7_LIBS 
sms
http_info
topology
tun
uci_config
evil
json
table
)


foreach(loopVar IN LISTS BMX7_LIBS)
	add_library(bmx7_${loopVar} SHARED src/lib/bmx7_${loopVar}/${loopVar}.c )
endforeach()


add_library(bmx7_iwinfo      SHARED src/lib/bmx7_iwinfo/bmx7_iwinfo.c )
target_link_libraries(bmx7_iwinfo PRIVATE iw)
target_compile_definitions(bmx7_iwinfo PRIVATE HAVE_IWINFO_THR )

target_link_libraries(bmx7_json PRIVATE json-c)

add_library(bmx7_table       SHARED src/lib/bmx7_table/table.c )
target_compile_definitions(bmx7_table PRIVATE common )
target_link_libraries(bmx7_table PRIVATE common)
