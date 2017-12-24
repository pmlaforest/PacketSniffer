.h and .lib files can be found in the WpdPack directory

INSTALLATION
----------------------------------------------------------------------------------------------
1. To create an application that uses wpcap.dll with Microsoft Visual C++, follow these steps:

Include the file pcap.h at the beginning of every source file that uses the functions exported by library.
If your program uses Win32 specific functions of WinPcap, remember to include WPCAP among the preprocessor definitions.
If your program uses the remote capture capabilities of WinPcap, add HAVE_REMOTE among the preprocessor definitions. Do not include remote-ext.h directly in your source files.
Set the options of the linker to include the wpcap.lib library file specific for your target (x86 or x64). wpcap.lib for x86 can be found in the \lib folder of the WinPcap developer's pack, wpcap.lib for x64 can be found in the \lib\x64 folder.
Set the options of the linker to include the winsock library file ws2_32.lib. This file is distributed with the C compiler and contains the socket functions for Windows. It is needed by some functions used by the samples in the tutorial.