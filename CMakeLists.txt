cmake_minimum_required(VERSION 3.22)
set(SC_MODULE vnc-snapshot)
project(simply-cpp-${SC_MODULE} HOMEPAGE_URL "https://github.com/roelofrossouw/simply-cpp-vnc-snapshot" LANGUAGES CXX)
include(cmake/sc_bootstrap.cmake)

option(SC_VNC_SNAPSHOT_BUILD_TESTS "Build simply-cpp-vnc-snapshot tests" ${PROJECT_IS_TOP_LEVEL})

get_sc_version()
message(STATUS "SimplyCPP ${SC_MODULE} Version: ${SC_VERSION}")

# sc::params for the program; sc::size_i/point_i for the screen; zlib for the PNG. DES (for VNC
# authentication) is our own: OpenSSL 3 only has it in the legacy provider.
find_or_install_package(sc-core simply-cpp-dev simply-cpp 4.0.0)
find_or_install_package(sc-geometry simply-cpp-geometry-dev simply-cpp-geometry 1.0.0)
find_or_install_package(ZLIB zlib1g-dev zlib)

set(SOURCE_OBJECTS)
set(SOURCE_LIBRARIES)
set(SOURCE_LINK_LIBRARIES)

# vnc.h is the public header: sc::vnc::client (RFB 3.3/3.7/3.8), sc::vnc::picture and its PNG.
add_sc_object(vnc
        LINK_LIBRARIES sc::sc-geometry ZLIB::ZLIB
        PUBLIC_LINK_LIBRARIES sc::sc-geometry ZLIB::ZLIB)

add_sc_libraries(DESCRIPTION "simply-cpp VNC (RFB) client for one screenshot of a VNC server, as PNG")
target_compile_features(sc-vnc-snapshot PUBLIC cxx_std_20)
target_compile_features(sc-vnc-snapshot-shared PUBLIC cxx_std_20)

install_sc_module(PATH_VARS CMAKE_INSTALL_INCLUDEDIR)
install(FILES cmake/SimplyCppFunctions.cmake cmake/sc_bootstrap.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sc-vnc-snapshot
        COMPONENT development)

if (SC_VNC_SNAPSHOT_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests sc-vnc-snapshot-test)
endif ()

# sc-vnc-snapshot, the program: one screenshot of a VNC server to a PNG file.
add_executable(sc-vnc-snapshot-program apps/sc-vnc-snapshot.cpp)
set_target_properties(sc-vnc-snapshot-program PROPERTIES OUTPUT_NAME sc-vnc-snapshot)
target_link_libraries(sc-vnc-snapshot-program PRIVATE sc::sc-vnc-snapshot-shared sc::sc-core)
target_compile_definitions(sc-vnc-snapshot-program PRIVATE SC_VNC_SNAPSHOT_VERSION="${SC_VERSION}")
sc_program_info(sc-vnc-snapshot-program)
install(TARGETS sc-vnc-snapshot-program RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT tools)
# sc_man_page() names the page after the target; the target can't be called sc-vnc-snapshot (the
# library is), so the page is written here the same way, as sc-vnc-snapshot.1.
set(man_extra "${CMAKE_CURRENT_SOURCE_DIR}/man/sc-vnc-snapshot.md")
set(man_page "${CMAKE_CURRENT_BINARY_DIR}/sc-vnc-snapshot.1")
add_custom_command(OUTPUT "${man_page}"
        COMMAND ${CMAKE_COMMAND} -E env "SC_PARAMS_MAN_PAGE=${man_extra}" sh -c "'$<TARGET_FILE:sc-vnc-snapshot-program>' > '${man_page}'"
        DEPENDS sc-vnc-snapshot-program "${man_extra}"
        COMMENT "Writing the man page sc-vnc-snapshot.1"
        VERBATIM)
add_custom_target(sc-vnc-snapshot-man ALL DEPENDS "${man_page}")
install(FILES "${man_page}" DESTINATION "${CMAKE_INSTALL_MANDIR}/man1" COMPONENT tools)

package_sc_module(DEV_DEPENDS "simply-cpp-dev (>= 4.0.0~)" "simply-cpp-geometry-dev (>= 1.0.0~)" zlib1g-dev)
