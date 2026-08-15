execute_process(COMMAND uname -r OUTPUT_VARIABLE KERNEL_RELEASE OUTPUT_STRIP_TRAILING_WHITESPACE)
set(KERNEL_DIR "/lib/modules/${KERNEL_RELEASE}/build")

set(KERNEL_MODULE_NAME xavcore_kfuncs)
set(KERNEL_MODULE_SOURCE ${KERNEL_MODULE_NAME}.c)
set(KERNEL_MODULE_OBJECT ${KERNEL_MODULE_NAME}.o)
set(KERNEL_MODULE_KOBJECT ${KERNEL_MODULE_NAME}.ko)

# We run make in the binary directory,
# so we need to create a link to the source file.
file(
    CREATE_LINK
    ${CMAKE_CURRENT_SOURCE_DIR}/${KERNEL_MODULE_SOURCE}
    ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL_MODULE_SOURCE}
    SYMBOLIC
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL_MODULE_KOBJECT}

    # Temporary KBuild Makefile.
    COMMAND echo "obj-m += ${KERNEL_MODULE_OBJECT}" > ${CMAKE_CURRENT_BINARY_DIR}/Makefile
    COMMAND echo "KBUILD_CFLAGS += -g -O2" >> ${CMAKE_CURRENT_BINARY_DIR}/Makefile
    COMMAND echo "all:" >> ${CMAKE_CURRENT_BINARY_DIR}/Makefile
    COMMAND
        echo "\tmake -C /lib/modules/${KERNEL_RELEASE}/build M=${CMAKE_CURRENT_BINARY_DIR} modules"
        >> ${CMAKE_CURRENT_BINARY_DIR}/Makefile

    # Call the kernel build system.
    COMMAND make

    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Building kernel module ${KERNEL_MODULE_NAME} using KBuild"
    VERBATIM

    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${KERNEL_MODULE_SOURCE}
)
add_custom_target(
    ${KERNEL_MODULE_NAME} ALL DEPENDS
    ${CMAKE_CURRENT_BINARY_DIR}/${KERNEL_MODULE_KOBJECT}
)

# Dummy target for IDE code check.
add_library(${KERNEL_MODULE_NAME}_dummy OBJECT ${KERNEL_MODULE_SOURCE})
target_include_directories(
    ${KERNEL_MODULE_NAME}_dummy PRIVATE
    /usr/local/include/myapp
    /lib/modules/${KERNEL_RELEASE}/build/source/include
)
set_target_properties(${KERNEL_MODULE_NAME}_dummy PROPERTIES EXCLUDE_FROM_ALL TRUE)
set_target_properties(${KERNEL_MODULE_NAME}_dummy PROPERTIES EXCLUDE_FROM_DEFAULT_BUILD TRUE)
