

add_requires("doctest")
add_requires("libsodium")

target("example")
    set_kind("binary")
    set_languages("cxx17")
    add_files("src/*.cpp",
              "example/*.cpp"   )
    add_includedirs("include")
    add_packages("libsodium")
