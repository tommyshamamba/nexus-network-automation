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

add_library(nexus_pkt SHARED src/nexus_pkt.c)
target_include_directories(nexus_pkt PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(nexus_pkt PRIVATE ${NX_WARN})
set_target_properties(nexus_pkt PROPERTIES C_VISIBILITY_PRESET default)

if(NX_SANITIZE)
  set(NX_SAN_FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  target_compile_options(nexus_pkt PRIVATE ${NX_SAN_FLAGS})
  target_link_options(nexus_pkt PRIVATE ${NX_SAN_FLAGS})
endif()

add_executable(nx-pcapstat tools/pcapstat.c)
target_link_libraries(nx-pcapstat PRIVATE nexus_pkt)
target_compile_options(nx-pcapstat PRIVATE ${NX_WARN})

include(CTest)
if(BUILD_TESTING)
  add_executable(test_nexus_pkt tests/test_nexus_pkt.c)
  target_link_libraries(test_nexus_pkt PRIVATE nexus_pkt)
  target_compile_options(test_nexus_pkt PRIVATE ${NX_WARN})
  if(NX_SANITIZE)
    target_compile_options(test_nexus_pkt PRIVATE ${NX_SAN_FLAGS})
    target_link_options(test_nexus_pkt PRIVATE ${NX_SAN_FLAGS})
  endif()
  add_test(NAME nexus_pkt_unit COMMAND test_nexus_pkt ${CMAKE_CURRENT_BINARY_DIR})
endif()

install(TARGETS nexus_pkt nx-pcapstat)
install(FILES include/nexus_pkt.h DESTINATION include)
