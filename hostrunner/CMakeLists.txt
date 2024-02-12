cmake_minimum_required(VERSION 3.12)
project(linrunner C CXX)

set(WITH_MINIIO ${CMAKE_CURRENT_LIST_DIR}/../miniio)

if(EMSCRIPTEN)
    set(IO_BACKEND stub)
else()
    set(IO_BACKEND uv) 
endif()

if(${IO_BACKEND} STREQUAL uv) 
    if(WITH_UV)
        add_subdirectory(${WITH_UV} uv)
        if(CYGWIN)
            # WAR: Cygwin libc cannot be used with gnu90
            set_property(TARGET uv_a PROPERTY C_STANDARD 11)
        endif()
        set(uvlib uv_a)
    else()
        find_library(uv REQUIRED)
        set(uvlib uv)
    endif()
endif()


# tentative locations
set(kmdist ${CMAKE_CURRENT_LIST_DIR}/../../kmdist)
set(umdist ${CMAKE_CURRENT_LIST_DIR}/../../umdist)
set(wabt ${CMAKE_CURRENT_LIST_DIR}/../../wabt)
set(wasm2c ${wabt}/wasm2c)

include_directories(${wasm2c} mempoolite .. ${kmdist}
  # for w2cfixup
  ${CMAKE_CURRENT_LIST_DIR}/../umwrap/wasm2c
  )

set(CMAKE_CXX_STANDARD 20)

# Scan
set(modmap_file ${umdist}/wasmlinux/modcache/modmap.tsv)
configure_file(${modmap_file} ${CMAKE_CURRENT_BINARY_DIR}/modmap.now.tsv)
file(STRINGS ${modmap_file} modmap)

function(hashpath var hash)
  if("${hash}" MATCHES "(..)(..)(.*)")
    set(${var} ${CMAKE_MATCH_1}/${CMAKE_MATCH_2}/${CMAKE_MATCH_3}
      PARENT_SCOPE)
  else()
    message(FATAL_ERROR "Invalid hashpath: ${hash}")
  endif()
endfunction()

set(userincdirs)
set(usermods)
foreach(m ${modmap})
    if(${m} MATCHES "([^\t]*)\t(.*)")
        set(hash ${CMAKE_MATCH_1})
        hashpath(hp ${hash})
        set(modname ${CMAKE_MATCH_2})
        list(APPEND usermods "${umdist}/wasmlinux/modcache/${hp}/${modname}_base_w2c.c")
        list(APPEND userincdirs "${umdist}/wasmlinux/modcache/${hp}")
    endif()
endforeach()

include_directories(${userincdirs}
    ${WITH_MINIIO}/include)

if(EMSCRIPTEN)
    set(CMAKE_EXECUTABLE_SUFFIX ".html")
endif()

add_executable(runner
    ${WITH_MINIIO}/src/miniio_${IO_BACKEND}.c
    ${wasm2c}/wasm-rt-impl.c
    ${kmdist}/kernel.c
    ${usermods}
    mempoolite/mplite.c
    runner.cpp
    userctx_w2c.c
    glue_modules.c
)

if(EMSCRIPTEN)
    target_compile_options(runner
        PRIVATE -pthread -fexceptions -fwasm-exceptions)
    set_property(TARGET runner
        PROPERTY LINK_OPTIONS -pthread -sPROXY_TO_PTHREAD 
        -fwasm-exceptions
        # 512MiB
        -sINITIAL_MEMORY=536870912)

endif()

# FIXME: Migrate to WASM Exceptions
target_compile_definitions(runner PRIVATE WASM_RT_USE_STACK_DEPTH_COUNT=0)

if(${IO_BACKEND} STREQUAL uv)
    target_link_libraries(runner ${uvlib})
endif()

if(MSVC)
    # /EHs /EHc-: extern "C" may throw exceptions
    # https://learn.microsoft.com/en-us/cpp/build/reference/eh-exception-handling-model
    target_compile_options(runner PRIVATE /EHsc-)
endif()
