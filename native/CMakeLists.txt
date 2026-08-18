cmake_minimum_required(VERSION 3.20)
project(turboheader_il2cpp C)
include(CheckCCompilerFlag)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
option(TURBOHEADER_BUILD_JNI "Build the JNI shared library" ON)
option(TURBOHEADER_STRICT_WARNINGS "Enable extended native compiler diagnostics" OFF)
option(TURBOHEADER_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)
option(TURBOHEADER_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

function(turboheader_add_checked_flag target flag)
  string(MAKE_C_IDENTIFIER "${flag}" flag_id)
  set(cache_var "TURBOHEADER_HAS_${flag_id}")
  check_c_compiler_flag("${flag}" "${cache_var}")
  if(${cache_var})
    target_compile_options(${target} PRIVATE "${flag}")
  endif()
endfunction()

function(turboheader_configure_target target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4)
    if(TURBOHEADER_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
    if(TURBOHEADER_STRICT_WARNINGS)
      foreach(flag IN ITEMS
          -Wformat=2
          -Wundef
          -Wshadow
          -Wconversion
          -Wsign-conversion
          -Wcast-align
          -Wcast-qual
          -Wcast-function-type
          -Wbad-function-cast
          -Wstrict-prototypes
          -Wmissing-prototypes
          -Wmissing-declarations
          -Wmissing-noreturn
          -Wpointer-arith
          -Wwrite-strings
          -Wvla
          -Walloca
          -Wswitch-enum
          -Wimplicit-fallthrough
          -Wdouble-promotion
          -Wnull-dereference
          -Wredundant-decls
          -Wunreachable-code)
        turboheader_add_checked_flag(${target} "${flag}")
      endforeach()
    endif()
    if(TURBOHEADER_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()

  if(TURBOHEADER_ENABLE_SANITIZERS)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
      message(FATAL_ERROR "TURBOHEADER_ENABLE_SANITIZERS requires GCC or Clang")
    endif()
    target_compile_options(${target} PRIVATE
      -O1 -g3 -fno-omit-frame-pointer -fsanitize=address,undefined)
    target_link_options(${target} PRIVATE -fsanitize=address,undefined)
  endif()
endfunction()

if(TURBOHEADER_BUILD_JNI)
  find_package(JNI REQUIRED)
  add_library(turboheader_il2cpp SHARED src/il2cpp_native.c)
  target_include_directories(turboheader_il2cpp PRIVATE include ${JNI_INCLUDE_DIRS})
  target_compile_definitions(turboheader_il2cpp PRIVATE I2C_JNI)
  turboheader_configure_target(turboheader_il2cpp)
  install(TARGETS turboheader_il2cpp
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin)
endif()

add_executable(il2cpp_native_cli src/il2cpp_native.c)
target_include_directories(il2cpp_native_cli PRIVATE include)
target_compile_definitions(il2cpp_native_cli PRIVATE I2C_CLI)
turboheader_configure_target(il2cpp_native_cli)
install(TARGETS il2cpp_native_cli RUNTIME DESTINATION bin)
