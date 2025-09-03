fn main() {
    // 通过 VC-LTL 兼容 winxp
    let vcltl_path = std::env::var("VCLTL_PATH")
        .ok()
        .and_then(|p| if p.is_empty() { None } else { Some(p) });
    if let Some(vcltl) = &vcltl_path {
        println!("cargo:warning=VC-LTL Path: {vcltl}");
        println!("cargo:rustc-link-search={vcltl}");
    }

    // 避免导入表中同时存在大写和小写的两个 kernel32.dll
    println!("cargo:rustc-cdylib-link-arg=/NODEFAULTLIB:kernel32");

    // 手动链接 MSVC runtime
    // 静态链接 vcruntime140.dll
    println!("cargo:rustc-link-lib=libvcruntime");
    // 动态链接 UCRT(api-ms-win-xxx.dll)，win10+ 已自带，没必要静态链接
    println!("cargo:rustc-link-lib=ucrt");
    // 静态链接 UCRT
    //println!("cargo:rustc-link-lib=libucrt");

    println!("cargo:rustc-cdylib-link-arg=/DEF:src/dll.def");

    println!("cargo::rerun-if-changed=src/wsock32.cpp");
    println!("cargo::rerun-if-changed=src/dll.def");
    println!("cargo::rerun-if-env-changed=VCLTL_PATH");

    let mut builder = cc::Build::new();
    builder
        .cpp(true)
        .file("src/wsock32.cpp")
        .define("UNICODE", None);
    if vcltl_path.is_none() {
        builder.define("MT", None);
    }
    builder.compile("wsock32");

    winresource::WindowsResource::new()
        .set("FileDescription", "IPX over UDP")
        .set("LegalCopyright", "github.com/wzv5")
        .compile()
        .unwrap();
}
