# psocrypt-cs
This library is a C# port of the network datastream encryption algorithms used by the Phantasy Star Online games. psocrypt-cs is derived from the work done by:

* Fuzziqer Software
* Sodaboy (Author of Tethealla)
* Lawrence Sebald (Author of Sylverant)

psocrypt-cs is largely an ad-verbatim port of the original encryption code with modifications to make it friendlier and more appropriate for C# server projects.

## FEATURES:
* Extremely simple - Plug into your project and go.
* Supports datastream encryption/decryption for most original PSO clients.
    * Phantasy Star Online PC/Dreamcast/Blueburst Patch Server
    * Phantasy Star Online: Blue Burst 
    * Phantasy Star Online Episode 1 & 2 (Gamecube) _(Written but not tested. Probably does not work, may be removed)_

## BUILD REQUIREMENTS:
* Visual Studio 2013 or later.
* .NET Framework 4.5.2

## BUILD INSTRUCTIONS:
* Build the project corresponding to the flavor of encryption you wish to utilize.
    - PSOCrypt-BB: Blue Burst
    - PSOCrypt-GC: Gamecube
    - PSOCrypt-PCDC: PC, Blueburst Patch, Dreamcast


## COPYRIGHT INFORMATION
Phantasy Star Online is copyright SEGA Corporation 2000-2017.

Original code implementation is copyright Fuzziqer Software, 2004.

Tethealla is licensed under the GPLv3, and Sylverant is licensed under the Affro GPLv3. 

This code is licensed under the GPL v3. You are free to distribute and use this library as you see fit.
Any modifications to this code must be licensed under the AGPLv3. Updates made to the source code must be provided in accordance with the terms of the license. No warranty or liability is provided with the use of this library. I cannot be held responsible or personally liable for any damages or data loss that may result by using this software.

A full copy of the GPLv3 license is provided alongside this library.
