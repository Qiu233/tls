# tls

`tls` is an https implementation in Lean 4, depending on OpenSSL.

# Build

Downstream users of this package **MUST** have a system-wide clang installed,
and prepend `LEAN_CC=clang` to `lake` commands, for example `LEAN_CC=clang lake build` / `LEAN_CC=clang lake exe ...`.

This is because the Lean's bundled clang won't find system openssl installation,
and that the bundled GLIBC is (currently, Lean v4.27.0 toolchain) much older than a system openssl would expect.

Other prerequisites include
* libuv >= 1.50.0
* libc++
* libc++-abi
