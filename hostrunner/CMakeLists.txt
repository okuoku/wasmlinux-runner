cmake_minimum_required(VERSION 3.12)
project(linrunner C CXX)

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

include_directories(${userincdirs})

add_executable(runner
    ${wasm2c}/wasm-rt-impl.c
    ${kmdist}/kernel.c
    ${usermods}
    mempoolite/mplite.c
    runner.cpp
    userctx_w2c.c
    glue_modules.c
)

if(MSVC)
    # /EHs /EHc-: extern "C" may throw exceptions
    # https://learn.microsoft.com/en-us/cpp/build/reference/eh-exception-handling-model
    target_compile_options(runner PRIVATE /EHsc-)
endif()
