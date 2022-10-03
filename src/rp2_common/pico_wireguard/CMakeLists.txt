if (DEFINED ENV{PICO_WG_LWIP_PATH} AND (NOT PICO_WG_LWIP_PATH))
    set(PICO_WG_LWIP_PATH $ENV{PICO_WG_LWIP_PATH})
    message("Using PICO_WG_LWIP_PATH from environment ('${PICO_WG_LWIP_PATH}')")
endif ()

if (NOT PICO_WG_LWIP_PATH)
    set(PICO_WG_LWIP_PATH ${PROJECT_SOURCE_DIR}/lib/wireguard-lwip)
    if (NOT EXISTS ${PICO_WG_LWIP_PATH}/${LWIP_TEST_PATH})
        message(WARNING "wireguard-lwip submodule has not been initialized; Pico W wireless support will be unavailable
hint: try 'git submodule update --init' from your SDK directory (${PICO_SDK_PATH}).")
    endif()
elseif (NOT EXISTS ${PICO_WG_LWIP_PATH}/${LWIP_TEST_PATH})
    message(WARNING "PICO_WG_LWIP_PATH specified but content not present.")
endif()

if (EXISTS ${PICO_WG_LWIP_PATH}/${LWIP_TEST_PATH})
    message("wireguard-lwip available at ${PICO_WG_LWIP_PATH}")

    pico_register_common_scope_var(PICO_WG_LWIP_PATH)

    # The files needed for wireguard-lwip.
    add_library(pico_wireguard INTERFACE)
    target_sources(pico_wireguard INTERFACE
            ${PICO_WG_LWIP_PATH}/src/wireguard.c
            ${PICO_WG_LWIP_PATH}/src/wireguardif.c
            ${PICO_WG_LWIP_PATH}/src/crypto.c
            ${PICO_WG_LWIP_PATH}/src/crypto/refc/blake2s.c
            ${PICO_WG_LWIP_PATH}/src/crypto/refc/chacha20.c
            ${PICO_WG_LWIP_PATH}/src/crypto/refc/chacha20poly1305.c  
            ${PICO_WG_LWIP_PATH}/src/crypto/refc/poly1305-donna.c  
            ${PICO_WG_LWIP_PATH}/src/crypto/refc/x25519.c
            ${PICO_WG_LWIP_PATH}/src/crypto/cortex/scalarmult.c
            ${PICO_WG_LWIP_PATH}/src/crypto/cortex/mul.s
            ${PICO_WG_LWIP_PATH}/src/crypto/cortex/sqr.s
            ${PICO_WG_LWIP_PATH}/src/crypto/cortex/cortex_m0_mpy121666.s
            ${PICO_WG_LWIP_PATH}/src/crypto/cortex/cortex_m0_reduce25519.s
            ${CMAKE_CURRENT_LIST_DIR}/wireguard-platform.c
            )
    target_include_directories(pico_wireguard INTERFACE
            ${PICO_WG_LWIP_PATH}/src)
    target_compile_options(pico_wireguard INTERFACE
            -DWG_LWIP_USE_CORTEX_M0_CRYPTO)

    pico_promote_common_scope_vars()
endif()
