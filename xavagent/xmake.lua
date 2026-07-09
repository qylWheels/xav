target("xavagent")
    set_kind("binary")
    add_files("**.cpp")
    add_deps("xavlib")
    add_packages(
        "leveldb", "cryptopp", "wxwidgets", "oatpp", "protobuf-cpp",
        "spdlog", "yaml-cpp", "yara", "outcome", "cereal"
    )
    add_deps("xavcommon")

    on_run(function (target)
        import("core.base.option")
        os.cd(os.projectdir()) 
        os.exec(target:targetfile())
    end)