

add_requires("doctest")
add_requires("libsodium")

target("example")
    set_kind("binary")
    set_default(false)
    set_languages("cxx17")
    add_files("example/*.cpp"   )
    add_includedirs("include")
    add_packages("libsodium")
    add_deps("static_lib")
    if is_plat("windows")then
        add_cxxflags("/permissive-","/W4")
    end
    after_build(function( target)
        os.cp(target:targetfile(), "$(projectdir)/bin/")
    end)

target("test")
    set_kind("binary")
    set_default(false)
    set_languages("cxx17")
    add_files("test/*.cpp")
    add_includedirs("include")
    add_packages("libsodium", "doctest")
    add_deps("static_lib")
    if is_plat("windows")then
        add_cxxflags("/permissive-","/W4")
    end
    after_build(function( target)
        os.cp(target:targetfile(), "$(projectdir)/bin/")
    end)

target("static_lib")
    set_kind("static")
    set_default(true)
    set_languages("cxx17")
    add_files("src/*.cpp")
    add_includedirs("include")
    add_packages("libsodium")
    if is_plat("windows")then
        add_cxxflags("/permissive-","/W4")
    end
    on_install(function(package )
        os.cp("include/*", os.installdir("include"))
    end)