# psocrypt-cs
This library is a C# port of the encryption algorithms used by the Phantasy Star Online games.

Phantasy Star Online is copyright SEGA Corporation 2000-2017.

Original implimentations that were referenced and used to write this version were written by Fuzziqer Software, Sodaboy (Tethealla), and
Lawrence Sebald (Sylverant). The original C code and implimentation is copyright Fuzziqer Software, 2004.

Tethealla is licensed under the GPLv3, and Sylverant is licensed under the Affro GPLv3. 

Implimentation is mostly ad-verbatim from the original code.

This code is licensed under the Affro GPL v3. You are free to distribute and use this library as you see fit.
Any modifications to this code must be licensed under the AGPLv3. Updates made to the source code must be provided in accordance with the terms of the license. No warranty or liability is provided with the use of this library. I cannot be held responsible or personally liable for any damages or data loss that may result by using this software.

A full copy of the AGPLv3 license is provided alongside this library.

##SUPPORTED:
* Phantasy Star Online PC/Dreamcast (Any version for these platforms that uses the standard PC/DC encryption should work.
* Phantasy Star Online Gamecube _(experimental and untested; probably does not work right now)_
* Phantasy Star Online: Blue Burst

##FEATURES:
* Safe reimplimentation of original C code. (Does not utilize any C# pointers or any unsafe code.)
* Object oriented design.

##BUILD REQUIREMENTS:
* Visual Studio 2013 or later.
* .NET Framework 4.5.2

##BUILD INSTRUCTIONS:
* Build the project corresponding to the flavor of encryption you wish to utilize.
    - PSOCrypt-BB: Blue Burst
    - PSOCrypt-GC: Gamecube
    - PSOCrypt-PCDC: PC, Blueburst Patch, Dreamcast
