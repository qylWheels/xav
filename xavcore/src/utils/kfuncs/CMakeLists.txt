# Linux headers.
execute_process(COMMAND uname -r OUTPUT_VARIABLE KERNEL_RELEASE OUTPUT_STRIP_TRAILING_WHITESPACE)
set(KERNEL_DIR "/lib/modules/${KERNEL_RELEASE}/build")

# Kernel module name, source file and object file.
set(KERNEL_MODULE_NAME xav_kfuncs)
set(KERNEL_MODULE_SOURCES ${KERNEL_MODULE_NAME}.c)
set(KERNEL_MODULE_OBJECTS ${KERNEL_MODULE_NAME}.o)

# Target.
add_custom_target(${KERNEL_MODULE_NAME} ALL
    # Temporary KBuild Makefile.
    COMMAND echo "obj-m += ${KERNEL_MODULE_OBJECTS}" > ${CMAKE_CURRENT_BINARY_DIR}/Makefile
    COMMAND echo "KBUILD_CFLAGS += -g -O2" >> ${CMAKE_CURRENT_BINARY_DIR}/Makefile
    COMMAND echo "${KERNEL_MODULE_NAME}-objs := ${KERNEL_MODULE_SOURCES}" >> ${CMAKE_CURRENT_BINARY_DIR}/Makefile
    COMMAND
        echo "make -C /lib/modules/${KERNEL_RELEASE}/build M=${CMAKE_CURRENT_BINARY_DIR} modules"
        >> ${CMAKE_CURRENT_BINARY_DIR}/Makefile

    # Call the kernel build system.
    COMMAND make
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Building kernel module ${KERNEL_MODULE_NAME} using KBuild"
    VERBATIM
)
