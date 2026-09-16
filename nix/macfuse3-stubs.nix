# Build-time link stubs for macFUSE's libfuse3 (fuse3.pc), mirroring
# what nixpkgs macfuse-stubs provides for libfuse2 (fuse.pc, which ships
# no fuse3.pc). Same split as that package: this only covers compiling
# and linking. The stub dylib carries the system install name
# (/usr/local/lib/libfuse3.dylib), so the binary loads the real system
# macFUSE at runtime, which nix cannot provide. No headers are shipped:
# fuser carries its own checked-in libfuse3 bindings, so the build only
# needs pkg-config resolution plus the link stub. Revisit if a nixpkgs
# macfuse-stubs ever ships fuse3.pc itself.
#
# A compiled stub dylib is used instead of a .tbd: the nix toolchain's
# ld64 rejects both tapi-tbd-v2 (nixpkgs macfuse-stubs format) and
# tapi-tbd-v4 as unknown file formats, so text stubs cannot link here.
{ stdenv }:
stdenv.mkDerivation {
  name = "macfuse3-stubs";
  dontUnpack = true;
  buildPhase = ''
    cat > stub.c <<'EOF'
    #include <stddef.h>
    void *fuse_session_new(void *args, void *ops, size_t op_size, void *userdata) {
        (void)args; (void)ops; (void)op_size; (void)userdata;
        return (void *)0;
    }
    int fuse_session_mount(void *se, char *mountpoint) {
        (void)se; (void)mountpoint;
        return 0;
    }
    int fuse_session_fd(void *se) {
        (void)se;
        return -1;
    }
    void fuse_session_unmount(void *se) { (void)se; }
    void fuse_session_destroy(void *se) { (void)se; }
    EOF
    $CC -dynamiclib \
      -install_name /usr/local/lib/libfuse3.dylib \
      -current_version 4.0.0 -compatibility_version 4.0.0 \
      -o libfuse3.dylib stub.c
  '';
  installPhase = ''
    mkdir -p $out/lib/pkgconfig
    cp libfuse3.dylib $out/lib/
    cat > $out/lib/pkgconfig/fuse3.pc <<EOF
    prefix=$out
    exec_prefix=\''${prefix}
    libdir=\''${exec_prefix}/lib

    Name: fuse3
    Description: Filesystem in Userspace (macFUSE link stub)
    Version: 3.0.0
    Libs: -L\''${libdir} -lfuse3 -lpthread
    Libs.private: -liconv -licucore
    EOF
  '';
}
