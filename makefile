all:
	meson setup build --strip --cross-file crossfile.txt -Dheaders_only=false -Ddefault_library=static -Dbuild_tests=false -Dposix_option=enabled -Dlinux_option=disabled -Dglibc_option=enabled -Dbsd_option=enabled -Dprefix=/opt/mlibc/ --wipe
	ninja -C build
	ninja -C build install