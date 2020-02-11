# MUSCA_A1_NS prebuilt secure binaries

This directory tree contains Secure images released under Permissive Binary License.

Built by mbed-cli using GNU Arm Embedded - version 6.3.1

These images were compiled by the following command:

## mcuboot.bin
### Repository
https://github.com/Patater/trusted-firmware-m.git
### Commit SHA
02a132b30992f25b9ea6d649250b35a3718d0f0d
```sh
cmake ../ -G"Unix Makefiles" -DTARGET_PLATFORM=MUSCA_A -DCOMPILER=ARMCLANG -DCMAKE_BUILD_TYPE=Debug
make
```

## tfm.bin

```sh
mbed compile -t GCC_ARM -m ARM_MUSCA_A1_S --app-config tools/psa/tfm/mbed_app.json --profile release
```

To update the prebuilt binaries run the previous commands.
