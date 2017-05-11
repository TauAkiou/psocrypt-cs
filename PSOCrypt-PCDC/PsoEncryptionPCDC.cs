using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Remoting.Contexts;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

/*   Phantasy Star Online: PC/DC/BBPatch Encryption Library
 *   
 *   First written by Fuzziqer Software in C and ported to C# by TauAkiou. Code primarily adapted from the Tethealla (Larry Chatman Jr.) + Sylverant (Lawrence Siebald) projects.
 *   Implimentation is mostly ad-verbatim from the original code.
 * 
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *   
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *   
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 *   Original code copyright Fuzziqer Software 2004. Most code is attributed to Fuzziqer unless stated otherwise.
 * 
 *   Phantasy Star Online is copyright SEGA 2000-2017.
 * 
 *   This library object supports Phantasy Star Online PC, Phantasy Star Online Dreamcast. This library is also used by the Phantasy Star Online: Blue Burst patch server.
 *  
 *   IMPORTANT NOTES:
 *  
 *   This encryption algorithm is designed to work on 4 byte blocks of data at a time. It is up to the developer to ensure that the length of
 *   streams passed to the encryption object are divisible by 4. The encryption algorithm will throw an exception if the
 *   stream is not properly divisible by 4.
 *  
 *   pc_posn is advanced on both the client and server side for each uint crypted by the engine. The client will typically only crypt
 *   however many bytes the command sent (ushort, first two bytes of an incoming packet) plus any bytes required to make the command stream
 *   size divisible by 4. If the server crypts too many or too few bytes, the encryption will fall out of sync and the next packet recieved/sent
 *   will crypt to garbage. Therefore, it is the developer's responsibility to keep the encryption in sync by only crypting the exact number of bytes
 *   expected by the other side of the connection.
 */


namespace PSOCrypt
{

    public class PsoEncryptionPCDC
    {
        /* Key encryption stream. */
        private uint[] keys = new uint[57];
        /* PSOPC/Patch Cryptography Position */
        private uint pc_posn;
        // Uint store of the seed.
        public uint Seed { get; private set; }
        public byte[] SeedBytes { get
            {
                return BitConverter.GetBytes(Seed);
            }
        }


        /*
         * PsoEncryptionPCDC()
         * 
         * Initializes the encryption object using a random seed provided by RNGCryptoServiceProvider.
         *
         */
        public PsoEncryptionPCDC() // This constructor autogenerates the seed and uses it for crypto init.
        {
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                var seedbyt = new byte[4];
                rng.GetBytes(seedbyt);
                Seed = BitConverter.ToUInt32(SeedBytes, 0);
                CreateKeys(Seed);
            }
        }

        /* PsoEncryptionPCDC(uint initseed)
        * 
        * Initializes the encryption object using a discrete seed provded by the user.
        * 
        * This is included primarily for testing purposes.
        * 
        */
        public PsoEncryptionPCDC(uint initseed)
        {
            Seed = initseed;
            CreateKeys(Seed);
        }


        /* uint LE32(uint x)
        * 
        * Little Endian -> Big Endian conversion macro for unsigned integers, ported from Sylverant. Original copyright Lawrence Siebald, 2016.
        * 
        * Please look at EncryptionHeader_Sylverant.txt supplied with this document if you wish to see the header supplied with the original code.
        * 
        * This code may not matter as BitConverter may already account for Endian-ness.
        * 
        * TODO: Look into this and make a decision on whether or not this needs to be kept.
        */
        private uint LE32(uint x) // Big Endian conversion code? Consider removing this from the source?
        {
            if (!BitConverter.IsLittleEndian) // No idea if this will even work at all; testing required. .NET may even handle this store automatically, but I can't be too sure. Is there even a Big Endian computer that runs .NET?
            {
                x = (((x >> 24) & 0x00FF) | 
                 ((x >> 8) & 0xFF00) |
                 ((x & 0xFF00) << 8) |
                 ((x & 0x00FF) << 24));
                 return x;
            }
            return x;
        }


        /* void MixKeys()
         * 
         * Performs key mixing during keystore creation and when the end of the keystore is reached.
         * 
         * Called during object creation by Create() and by NextKey().
         */

        private void MixKeys()
        {

            uint esi, edi, eax, ebp, edx;
            edi = 1;
            edx = 0x18;
            eax = edi;
            while (edx > 0)
            {
                esi = keys[eax + 0x1F];
                ebp = keys[eax];
                ebp = ebp - esi;
                keys[eax] = ebp;
                eax++;
                edx--;
            }

            edi = 0x19;
            edx = 0x1F;
            eax = edi;
            while (edx > 0)
            {
                esi = keys[eax - 0x18];
                ebp = keys[eax];
                ebp = ebp - esi;
                keys[eax] = ebp;
                eax++;
                edx--;
            }
        }

        /* void CRYPT_PC_CreateKeys(uint seedval)
         * 
         * Generates encryption keystore.
         * 
         * Called on object creation.
         */
        private void CreateKeys(uint seedval)
        {

            uint esi, ebx, edi, eax, edx, var1;
            esi = 1;
            ebx = seedval;
            edi = 0x15;
            keys[56] = ebx;
            keys[55] = ebx;

            while (edi <= 0x46E)
            {
                eax = edi;
                var1 = eax/55;
                edx = eax - (var1*55);
                ebx = ebx - esi;
                edi = edi + 0x15;
                keys[edx] = esi;
                esi = ebx;
                ebx = keys[edx];
            }
            for (int x = 0; x < 4; x++)
            {
                MixKeys();
            }
            pc_posn = 56;
        }

        /* private uint GetNextKey()
         * 
         * Gets the next encryption key from the keystore.
         * 
         * Called by the Crypt() method.
         */
        private uint GetNextKey()
        {
            uint re;
            if (pc_posn == 56)
            {
                MixKeys();
                pc_posn = 1;
            }
            re = keys[pc_posn];
            pc_posn++;
            return re;
        }

        /* byte[] Crypt(byte[] data, int offset, int size)
         * 
         * Runs crypto on the provided stream and returns the resulting byte stream.
         * 
         * Note that this method handles both encryption and decryption for the engine.
         * 
         */
        public byte[] Crypt(byte[] data, int offset, int size)
        {

            using (MemoryStream cryptoStream = new MemoryStream())
            {
                var dataConv = data;
                uint tmp;
                for (int x = offset; x < size; x += 4)
                {
                    tmp = BitConverter.ToUInt32(dataConv, x);
                    tmp = tmp ^ GetNextKey();
                    byte[] clear = BitConverter.GetBytes(tmp);
                    cryptoStream.Write(clear, 0, 4);
                }
                return (cryptoStream.ToArray());
            }
            
        }

        int Combine16To32(ushort x, ushort y) // Required to convert two ushorts into a single int32. (Should be uint32?)
        {
            byte[] mergeBytes = new byte[4];
            mergeBytes[0] = BitConverter.GetBytes(x)[0];
            mergeBytes[1] = BitConverter.GetBytes(x)[1];
            mergeBytes[2] = BitConverter.GetBytes(y)[0];
            mergeBytes[3] = BitConverter.GetBytes(y)[1];
            return (BitConverter.ToInt32(mergeBytes, 0));
        }

    }

}
