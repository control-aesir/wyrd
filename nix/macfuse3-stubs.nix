# Build-time link stubs for macFUSE's libfuse3 (fuse3.pc), mirroring
# what nixpkgs macfuse-stubs provides for libfuse2 (fuse.pc, which ships
# no fuse3.pc). Same split as that package: this only covers compiling
# and linking. The .tbd declares the system install name
# (/usr/local/lib/libfuse3.dylib), so the binary loads the real system
# macFUSE at runtime, which nix cannot provide. No headers are shipped:
# fuser carries its own checked-in libfuse3 bindings, so the build only
# needs pkg-config resolution plus the link stub. Revisit if a nixpkgs
# macfuse-stubs ever ships fuse3.pc itself.
{ runCommand }:
runCommand "macfuse3-stubs" { } ''
  mkdir -p $out/lib/pkgconfig
  cat > $out/lib/pkgconfig/fuse3.pc <<EOF
  prefix=$out
  exec_prefix=''${prefix}
  libdir=''${exec_prefix}/lib

  Name: fuse3
  Description: Filesystem in Userspace (macFUSE link stub)
  Version: 3.0.0
  Libs: -L''${libdir} -lfuse3 -lpthread
  Libs.private: -liconv -licucore
  EOF
  cat > $out/lib/libfuse3.tbd <<'EOF'
  --- !tapi-tbd-v2
  archs:           [ x86_64, arm64 ]
  platform:        macosx
  flags:           [ not_app_extension_safe ]
  install-name:    '/usr/local/lib/libfuse3.dylib'
  current-version: 4.0.0
  compatibility-version: 4.0.0
  objc-constraint: none
  exports:
    - archs:           [ x86_64, arm64 ]
      symbols:         [ _fuse_session_destroy, _fuse_session_fd,
                         _fuse_session_mount, _fuse_session_new,
                         _fuse_session_unmount ]
  EOF
''
