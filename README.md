# crypto-key
The project report of dynamic/static analysis using HyperDbg and angr

## Description
Given a crypto key and a crypto program crunching on it, write a tool that dumps all the instructions in the program that process data that depends on the key.

## Implementation
Two different approaches have been chosen to implement this project. The first one is a Dynamic Analysis approach while the second method is static. The dynamic analysis is done by using the HyperDbg debugger and for the static analysis method, angr is used.

## Description
Given a crypto key and a crypto program crunching on it, write a tool that dumps all the instructions in the program that process data that depends on the key.

## Limitations
This approach is pretty okay if the target program is not encrypted/packed/protected. Even though we can still extract instructions even if the program is packed, however, an anti-debug method might try to access the user-input buffer thousands of times in order to obfuscate the normal procedure. The other limitation is that the programmer might move the buffer several times in the memory and in these cases, the reverse engineer might use some manual investigation to find the address of the new buffers.

## Report
Please see the [report](https://github.com/SinaKarvandi/crypto-key/blob/main/report.pdf) for more details.

## License
crypto-key is licensed under a **GPLv3** license.
