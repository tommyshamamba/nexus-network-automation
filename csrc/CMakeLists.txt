cmake_minimum_required(VERSION 3.16)
project(nexus_pkt VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(NX_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(NX_WERROR "Treat warnings as errors" ON)

set(NX_WARN -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion
            -Wstrict-prototypes -Wmissing-prototypes)
if(NX_WERROR)
  list(APPEND NX_WARN -Werror)
endif()

# Sanitizers are applied to every target: with ASan the runtime must be linked
# into the executables (gcc refuses to start otherwise, clang leaves the shared
# library's __asan_* references unresolved).
if(NX_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()

add_library(nexus_pkt SHARED src/nexus_pkt.c)
target_include_directories(nexus_pkt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(nexus_pkt PRIVATE ${NX_WARN})
set_target_properties(nexus_pkt PROPERTIES C_VISIBILITY_PRESET default)

add_executable(nx-pcapstat tools/pcapstat.c)
target_link_libraries(nx-pcapstat PRIVATE nexus_pkt)
target_compile_options(nx-pcapstat PRIVATE ${NX_WARN})

include(CTest)
if(BUILD_TESTING)
  add_executable(test_nexus_pkt tests/test_nexus_pkt.c)
  target_link_libraries(test_nexus_pkt PRIVATE nexus_pkt)
  target_compile_options(test_nexus_pkt PRIVATE ${NX_WARN})
  add_test(NAME nexus_pkt_unit COMMAND test_nexus_pkt ${CMAKE_CURRENT_BINARY_DIR})
  add_test(NAME pcapstat_sample
           COMMAND nx-pcapstat ${CMAKE_CURRENT_SOURCE_DIR}/../examples/pcap/sample.pcap)
  set_tests_properties(pcapstat_sample PROPERTIES PASS_REGULAR_EXPRESSION "packets=204")
endif()

install(TARGETS nexus_pkt nx-pcapstat)
install(FILES include/nexus_pkt.h DESTINATION include)
