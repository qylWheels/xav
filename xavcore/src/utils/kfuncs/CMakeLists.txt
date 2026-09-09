set(KERNEL_MODULE_NAME xavcore_kfuncs)
set(KERNEL_MODULE_SOURCE ${KERNEL_MODULE_NAME}.c)

# DKMS registration identity
set(XAVCORE_KFUNCS_DKMS_NAME "xavcore-kfuncs")
set(XAVCORE_KFUNCS_DKMS_VERSION "0.1.0")
set(XAVCORE_KFUNCS_DKMS_DIR
    "${XAVCORE_KFUNCS_DKMS_NAME}-${XAVCORE_KFUNCS_DKMS_VERSION}"
)
# Relative-to /usr source destination used by this directory's install(), plus
# the /usr-anchored absolute path a deb control script would need. Expose the
# absolute one to the enclosing scopes too (src/utils, src, top-level) so the
# root CMakeLists could reconstitute it if ever needed.
set(XAVCORE_KFUNCS_DKMS_SRC_DEST
    "src/${XAVCORE_KFUNCS_DKMS_NAME}/${XAVCORE_KFUNCS_DKMS_DIR}"
)
set(XAVCORE_KFUNCS_DKMS_SRC_DIR
    "/usr/${XAVCORE_KFUNCS_DKMS_SRC_DEST}" PARENT_SCOPE)

# IDE / clangd helper: let the kernel header be resolved for dbg.
execute_process(
    COMMAND uname -r
    OUTPUT_VARIABLE KERNEL_REBUILD_REL
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
add_library(${KERNEL_MODULE_NAME}_dummy OBJECT ${KERNEL_MODULE_SOURCE})
target_include_directories(
    ${KERNEL_MODULE_NAME}_dummy PRIVATE
    /lib/modules/${KERNEL_REBUILD_REL}/build/source/include
)
set_target_properties(${KERNEL_MODULE_NAME}_dummy PROPERTIES
    EXCLUDE_FROM_ALL TRUE
    EXCLUDE_FROM_DEFAULT_BUILD TRUE
)

# Installation: ship the module *source* tree to /usr/src for DKMS.
install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/${KERNEL_MODULE_SOURCE}
        ${CMAKE_CURRENT_SOURCE_DIR}/Makefile
        ${CMAKE_CURRENT_SOURCE_DIR}/dkms.conf
    DESTINATION ${XAVCORE_KFUNCS_DKMS_SRC_DEST}
)
