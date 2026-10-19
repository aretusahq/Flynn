# Flynn for Android (Phase 2)

Not started. Android follows the iOS MVP on the same Rust core; see
[docs/development-plan.md](../docs/development-plan.md).

What Phase 2 adds here:

- A Gradle project with a Kotlin `VpnService` that implements the host
  traits from `core/flynn-dataplane/src/host.rs` through the generated
  Kotlin bindings (package `com.kasunben.flynn.core`):
  `HostPacketIo` over the TUN file descriptor, `HostSocketProtector` calling
  `VpnService.protect(fd)`, and `HostAppResolver` using
  `ConnectivityManager.getConnectionOwnerUid`.
- `libflynn_ffi.so` built with `cargo-ndk` into `jniLibs`.
- A Compose UI over the same Library facade the iOS app uses.

The core is already compiled for `aarch64-linux-android` and the Kotlin
bindings are generated on every `scripts/check.sh` run (output in
`build/bindings/kotlin`), so the core cannot drift away from Android while
iOS is built.
