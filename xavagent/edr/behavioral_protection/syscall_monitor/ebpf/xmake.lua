add_rules("mode.release", "mode.debug")
add_rules("platform.linux.bpf")

add_requires("linux-tools", {configs = {bpftool = true}})
add_requires("libbpf")
add_requires("llvm", {system = true})
set_toolchains("@llvm")

target("syscall_monitor")
    set_kind("binary")
    add_files("**.c")
    add_packages("linux-tools", "libbpf")
    set_license("GPL-2.0")
