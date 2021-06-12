

add_requires("doctest")
add_requires("libsodium")

target("example")
    set_kind("binary")
    set_languages("cxx17")
    add_files("src/*.cpp",
              "example/*.cpp"   )
    add_includedirs("include")
    add_packages("libsodium")
    if is_plat("windows")then
        add_cxxflags("/permissive-","/W4")
    end
    after_build(function( target)
        os.cp(target:targetfile(), "$(projectdir)/bin/")
    end)

target("test")
    set_kind("binary")
    set_languages("cxx17")
    add_files("src/*.cpp",
              "test/*.cpp")
    add_includedirs("include")
    add_packages("libsodium", "doctest")
    if is_plat("windows")then
        add_cxxflags("/permissive-","/W4")
    end
    after_build(function( target)
        os.cp(target:targetfile(), "$(projectdir)/bin/")
    end)
