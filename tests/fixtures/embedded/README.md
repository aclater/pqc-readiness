# Embedded and minimal rootfs fixtures (#217)

Captured 2026-10-14 from official release images. Each tarball was checked
against the publisher's `sha256sums` file before extraction.

| Fixture | Source | Expected values from |
| --- | --- | --- |
| `openwrt-24.10.8/usr/lib/opkg/status`, `openwrt-24.10.8/usr/lib/os-release` | `openwrt-24.10.8-x86-64-rootfs.tar.gz`, <https://downloads.openwrt.org/releases/24.10.8/targets/x86/64/> | `openwrt-24.10.8.opkg-list-installed.txt`: the image's own `opkg list-installed`, run inside a container imported from the same tarball (`podman import`, network off) |
| `openwrt-25.12.5/lib/apk/db/installed`, `openwrt-25.12.5/usr/lib/os-release` | `openwrt-25.12.5-x86-64-rootfs.tar.gz`, <https://downloads.openwrt.org/releases/25.12.5/targets/x86/64/> (OpenWrt moved from opkg to apk in 25.12) | `openwrt-25.12.5.apk-info-v.txt`: the image's own `apk info -v`, same method (apk's cache warnings removed) |
| `openwrt-24.10.8/etc/openwrt_release` (#258) | `openwrt-24.10.8-x86-64-rootfs.tar.gz` (as above) | the image's own file, copied verbatim; read when a tree has no `os-release` |
| `yocto-6.0.3-core-image-full-cmdline/etc/buildinfo`, `…/var/lib/rpm/rpmdb.sqlite.gz` (#227) | `core-image-full-cmdline-qemux86-64.rootfs-20260819091134.tar.zst`, <https://downloads.yoctoproject.org/releases/yocto/yocto-6.0.3/machines/qemu/qemux86-64/> | the image's `.manifest` (names and versions) and each header's own SOURCERPM tag |

Files are copied verbatim, except the Yocto rpm database: a copy of the
image's `rpmdb.sqlite` keeping 4 of its 444 packages (`libcrypto3`,
`libssl3`, `openssl-bin` from the `openssl` recipe, `libsmartcols1` from
`util-linux`). The other rows were deleted from every table with sqlite3,
then `VACUUM`; the kept header blobs are byte-for-byte the image's. Gzipped
like the other binary rpm fixtures. `etc/os-release` is a relative symlink to
`../usr/lib/os-release` in both OpenWrt images; the tests recreate it.

## Library strings

The tests build synthetic library files (a few bytes around the strings
below) under the real file names, so no binaries are committed:

| Library | File name in the image | Embedded string | Image |
| --- | --- | --- | --- |
| Mbed TLS | `/usr/lib/libmbedtls.so.3.6.6` (`libmbedtls.so.21` → it), `libmbedcrypto.so.3.6.6`, `libmbedx509.so.3.6.6` | none: OpenWrt builds without `MBEDTLS_VERSION_C`, so only the file name carries the release | OpenWrt 24.10.8 and 25.12.5 (package `libmbedtls21` 3.6.6-r2) |
| OpenSSL | `/usr/lib/libcrypto.so.3` | `OpenSSL 3.5.7 9 Jun 2026` | Yocto 6.0.3 `core-image-minimal` and `core-image-full-cmdline` (qemux86-64, <https://downloads.yoctoproject.org/releases/yocto/yocto-6.0.3/machines/qemu/qemux86-64/>; package `libcrypto3` 3.5.7 in the image manifest) |
| GnuTLS | `/usr/lib/libgnutls.so.30.41.1` | `Enabled GnuTLS 3.8.12 logging...` | Yocto 6.0.3 `core-image-full-cmdline` (package `libgnutls30` 3.8.12) |
| libgcrypt | `/usr/lib/libgcrypt.so.20.7.1` | `This is Libgcrypt 1.12.1 - The GNU Crypto Library` | Yocto 6.0.3 `core-image-full-cmdline` (package `libgcrypt` 1.12.1) |

The prebuilt Yocto images use rpm (`IMAGE_PKGTYPE = "rpm"`) and ship no
`os-release`, so their family resolves to `unknown` and the rpm database is
found by probing. `core-image-minimal` has no package database at all; its
OpenSSL version comes from `libcrypto.so.3` alone. Expected package counts
and versions come from each image's `.manifest` file published next to it.
