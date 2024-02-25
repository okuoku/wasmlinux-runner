cmake_minimum_required(VERSION 3.12)
project(linrunner C CXX)

set(WITH_MINIIO ${CMAKE_CURRENT_LIST_DIR}/../miniio)

if(EMSCRIPTEN)
    set(IO_BACKEND localnetstub)
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

if(EMSCRIPTEN)
    set(USE_MINITELNET on)
endif()

if(USE_MINITELNET)
    set(MINITELNET_EMBEDDED on)
    add_subdirectory(../minitelnet minitelnet)
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
    set(CMAKE_EXECUTABLE_SUFFIX ".mjs")
endif()

add_library(wasmmodules OBJECT
    ${kmdist}/kernel.c
    ${usermods}
    ${wasm2c}/wasm-rt-impl.c
    userctx_w2c.c
    glue_modules.c
    )

add_executable(runner
    ${WITH_MINIIO}/src/miniio_${IO_BACKEND}.c
    mempoolite/mplite.c
    runner.cpp
)

if(EMSCRIPTEN)
    set(em_opts
        # dwarf-5 is not compatible with wasm-opt (for now)
        -pthread -fexceptions -fwasm-exceptions -gsplit-dwarf)

    target_compile_options(runner PRIVATE ${em_opts})
    target_compile_options(wasmmodules PRIVATE ${em_opts})
    target_link_options(runner
        PRIVATE
        -pthread -sPROXY_TO_PTHREAD 
        -fwasm-exceptions
        -sWASM_BIGINT

        # 512MiB
        -sINITIAL_MEMORY=536870912

        # xterm-pty
        -sEXPORTED_FUNCTIONS=_malloc
        --js-library=${CMAKE_CURRENT_LIST_DIR}/../xterm-pty/emscripten-pty.js
        )
endif()

if(USE_MINITELNET)
    target_compile_definitions(runner PRIVATE
        USE_MINITELNET=1)
    target_link_libraries(runner minitelnet)
endif()

# FIXME: Migrate to WASM Exceptions
target_compile_definitions(runner PRIVATE WASM_RT_USE_STACK_DEPTH_COUNT=0)
target_compile_definitions(wasmmodules PRIVATE WASM_RT_USE_STACK_DEPTH_COUNT=0)

target_link_libraries(runner wasmmodules)
if(${IO_BACKEND} STREQUAL uv)
    target_link_libraries(runner ${uvlib})
endif()

if(MSVC)
    # /EHs /EHc-: extern "C" may throw exceptions
    # https://learn.microsoft.com/en-us/cpp/build/reference/eh-exception-handling-model
    target_compile_options(runner PRIVATE /EHsc-)
    target_compile_options(wasmmodules PRIVATE /EHsc-)
endif()
