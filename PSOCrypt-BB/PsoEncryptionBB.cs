using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using PSOCrypt.Tables;
using PSOCrypt.Exceptions;

namespace PSOCrypt
{
    public sealed class PsoEncryptionBB
    {
        /*   Phantasy Star Online: Blue Burst Library
         * 
         *   First written by Fuzziqer Software in C and ported to C# by TauAkiou.
         *   Code primarily adapted from the Tethealla (Larry Chatman Jr.) + Sylverant (Lawrence Siebald) projects.
         * 
         *   Tethealla is licensed under the GPLv3, and Sylverant is licensed under the Affro GPLv3.
         * 
         *   Implimentation is mostly ad-verbatim from the original code.
         * 
         *   This program is free software: you can redistribute it and/or modify
         *   it under the terms of the Affro GNU General Public License as published by
         *   the Free Software Foundation, either version 3 of the License, or
         *   (at your option) any later version.
         *   
         *   This program is distributed in the hope that it will be useful,
         *   but WITHOUT ANY WARRANTY; without even the implied warranty of
         *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
         *   Affro GNU General Public License for more details.
         *   
         *   You should have received a copy of the Affro GNU General Public License
         *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
         * 
         *   Original code copyright Fuzziqer Software 2004. Most code is attributed to Fuzziqer unless stated opherwise.
         * 
         *   Phantasy Star Online is copyright SEGA 2000-2017.
         * 
         *   This library object supports the Phantasy Star Online: Blue Burst Game itself (The patch server uses the PSOPC/DC engine, so both will be required for a Blue Burst server implimentation.)
         *  
         *   IMPORTANT NOTES:
         *  
         *   This encryption algorithm is designed to work on 8 byte blocks of data at a time. It is up to the developer to ensure that the length of
         *   streams passed to the encryption object are divisible by 8. The encryption algorithm will throw an exception if the
         *   stream does not meet this requirement.
         */

        private uint[] Keytable { get; }
        /* Key encryption stream. */
        private uint[] keys = new uint[1042];
        /* PSO:BB Cryptography Position */
        private uint bb_posn;
        /* Blue Burst Key Array */
        private uint[] _bbSeed = new uint[12];
        public byte[] Seed { get; private set; }


        /*
         * PsoEncryptionBB(IEncryptionTableBB keytbl)
         * 
         * Initializes the encryption object using a random seed provided by RNGCryptoServiceProvider
         * and the specified keytable.
         *
         */
        public PsoEncryptionBB(uint[] keytbl)
        {
            using(RNGCryptoServiceProvider crng = new RNGCryptoServiceProvider())
            {
                Keytable = keytbl;
                Seed = new byte[48];
                crng.GetBytes(Seed);
                CreateKeys(Seed);

            }
        }

        /*
        * PsoEncryptionBB(IEncryptionTableBB keytbl)
        * 
        * Initializes the encryption object using a discrete, user provided seed
        * and the specified keytable.
        *
        * This constructor is intended for testing purposes.
        * 
        */
        public PsoEncryptionBB(uint[] keytbl, byte[] initseed)
        {
            Keytable = keytbl;
            CreateKeys(initseed);
            Seed = initseed;
        }


        /* void CreateKeys(byte[] salt)
         * 
         * Initializes the local keystore using the provded salt.
         * 
         * Called on object construction.
         */
        void CreateKeys(byte[] salt)
        {
            uint eax, ecx, edx, ebx, ebp, esi, edi, ou, x;
            ushort dx;
            byte[] s = new byte[48];

            bb_posn = eax = ebx = 0;

            Buffer.BlockCopy(salt, 0, s, 0, s.Length);
            InitKeys(s);

            var bbtbl = new ushort[Keytable.Length * 2];
            var pcryp = new ushort[keys.Length * 2];


            Buffer.BlockCopy(Keytable, 0, bbtbl, 0, (Keytable.Length * sizeof(uint)));
            Buffer.BlockCopy(keys, 0, pcryp, 0, keys.Length * sizeof(uint));

            /*
             * This piece of code was pulled from Tethealla and is used to initialize the first 18 keys in the Tethealla keytable.
             *
             * The header from the Tethealla source is supplied alongside this package as "Tethealla_Header.txt".
             */

            for (ecx = 0; ecx < 0x12; ecx++)
            {
                dx = bbtbl[eax++];
                dx = (ushort)(((dx & (ushort)0xFF) << 8) + (dx >> 8));
                pcryp[ebx] = dx;
                dx = bbtbl[eax++];
                dx ^= pcryp[ebx++];
                pcryp[ebx++] = dx;
            }

            // End

            Buffer.BlockCopy(pcryp, 0, keys, 0, pcryp.Length * sizeof(ushort));

            Buffer.BlockCopy(Keytable, 18 * sizeof(uint) , keys, 18 * sizeof(uint), 1024 * sizeof(uint));
        
            ecx = 0;
            ebx = 0;

            while (ebx < 0x12)
            {
                ebp = ((uint)(s[ecx])) << 0x18;
                eax = ecx + 1;
                edx = eax - ((eax / 48) * 48);
                eax = (((uint)(s[edx])) << 0x10) & 0xFF0000;
                ebp = (ebp | eax) & 0xffff00ff;
                eax = ecx + 2;
                edx = eax - ((eax / 48) * 48);
                eax = (((uint)(s[edx])) << 0x8) & 0xFF00;
                ebp = (ebp | eax) & 0xffffff00;
                eax = ecx + 3;
                ecx = ecx + 4;
                edx = eax - ((eax / 48) * 48);
                eax = (uint)(s[edx]);
                ebp = ebp | eax;
                eax = ecx;
                edx = eax - ((eax / 48) * 48);
                keys[ebx] = keys[ebx] ^ ebp;
                ecx = edx;
                ebx++;
            }

            ebp = 0;
            esi = 0;
            ecx = 0;
            edi = 0;
            ebx = 0;
            edx = 0x48;

            while (edi < edx)
            {
                esi = esi ^ keys[0];
                eax = esi >> 0x18;
                ebx = (esi >> 0x10) & 0xff;
                eax = keys[eax + 0x12] + keys[ebx + 0x112];
                ebx = (esi >> 8) & 0xFF;
                eax = eax ^ keys[ebx + 0x212];
                ebx = esi & 0xff;
                eax = eax + keys[ebx + 0x312];

                eax = eax ^ keys[1];
                ecx = ecx ^ eax;
                ebx = ecx >> 0x18;
                eax = (ecx >> 0x10) & 0xFF;
                ebx = keys[ebx + 0x12] + keys[eax + 0x112];
                eax = (ecx >> 8) & 0xff;
                ebx = ebx ^ keys[eax + 0x212];
                eax = ecx & 0xff;
                ebx = ebx + keys[eax + 0x312];

                for (x = 0; x <= 5; x++)
                {
                    ebx = ebx ^ keys[(x * 2) + 2];
                    esi = esi ^ ebx;
                    ebx = esi >> 0x18;
                    eax = (esi >> 0x10) & 0xFF;
                    ebx = keys[ebx + 0x12] + keys[eax + 0x112];
                    eax = (esi >> 8) & 0xff;
                    ebx = ebx ^ keys[eax + 0x212];
                    eax = esi & 0xff;
                    ebx = ebx + keys[eax + 0x312];

                    ebx = ebx ^ keys[(x * 2) + 3];
                    ecx = ecx ^ ebx;
                    ebx = ecx >> 0x18;
                    eax = (ecx >> 0x10) & 0xFF;
                    ebx = keys[ebx + 0x12] + keys[eax + 0x112];
                    eax = (ecx >> 8) & 0xff;
                    ebx = ebx ^ keys[eax + 0x212];
                    eax = ecx & 0xff;
                    ebx = ebx + keys[eax + 0x312];
                }

                ebx = ebx ^ keys[14];
                esi = esi ^ ebx;
                eax = esi >> 0x18;
                ebx = (esi >> 0x10) & 0xFF;
                eax = keys[eax + 0x12] + keys[ebx + 0x112];
                ebx = (esi >> 8) & 0xff;
                eax = eax ^ keys[ebx + 0x212];
                ebx = esi & 0xff;
                eax = eax + keys[ebx + 0x312];

                eax = eax ^ keys[15];
                eax = ecx ^ eax;
                ecx = eax >> 0x18;
                ebx = (eax >> 0x10) & 0xFF;
                ecx = keys[ecx + 0x12] + keys[ebx + 0x112];
                ebx = (eax >> 8) & 0xff;
                ecx = ecx ^ keys[ebx + 0x212];
                ebx = eax & 0xff;
                ecx = ecx + keys[ebx + 0x312];

                ecx = ecx ^ keys[16];
                ecx = ecx ^ esi;
                esi = keys[17];
                esi = esi ^ eax;
                keys[(edi / 4)] = esi;
                keys[(edi / 4) + 1] = ecx;
                edi = edi + 8;
            }


            eax = 0;
            edx = 0;
            ou = 0;
            while (ou < 0x1000)
            {
                edi = 0x48;
                edx = 0x448;

                while (edi < edx)
                {
                    esi = esi ^ keys[0];
                    eax = esi >> 0x18;
                    ebx = (esi >> 0x10) & 0xff;
                    eax = keys[eax + 0x12] + keys[ebx + 0x112];
                    ebx = (esi >> 8) & 0xFF;
                    eax = eax ^ keys[ebx + 0x212];
                    ebx = esi & 0xff;
                    eax = eax + keys[ebx + 0x312];

                    eax = eax ^ keys[1];
                    ecx = ecx ^ eax;
                    ebx = ecx >> 0x18;
                    eax = (ecx >> 0x10) & 0xFF;
                    ebx = keys[ebx + 0x12] + keys[eax + 0x112];
                    eax = (ecx >> 8) & 0xff;
                    ebx = ebx ^ keys[eax + 0x212];
                    eax = ecx & 0xff;
                    ebx = ebx + keys[eax + 0x312];

                    for (x = 0; x <= 5; x++)
                    {
                        ebx = ebx ^ keys[(x * 2) + 2];
                        esi = esi ^ ebx;
                        ebx = esi >> 0x18;
                        eax = (esi >> 0x10) & 0xFF;
                        ebx = keys[ebx + 0x12] + keys[eax + 0x112];
                        eax = (esi >> 8) & 0xff;
                        ebx = ebx ^ keys[eax + 0x212];
                        eax = esi & 0xff;
                        ebx = ebx + keys[eax + 0x312];

                        ebx = ebx ^ keys[(x * 2) + 3];
                        ecx = ecx ^ ebx;
                        ebx = ecx >> 0x18;
                        eax = (ecx >> 0x10) & 0xFF;
                        ebx = keys[ebx + 0x12] + keys[eax + 0x112];
                        eax = (ecx >> 8) & 0xff;
                        ebx = ebx ^ keys[eax + 0x212];
                        eax = ecx & 0xff;
                        ebx = ebx + keys[eax + 0x312];
                    }

                    ebx = ebx ^ keys[14];
                    esi = esi ^ ebx;
                    eax = esi >> 0x18;
                    ebx = (esi >> 0x10) & 0xFF;
                    eax = keys[eax + 0x12] + keys[ebx + 0x112];
                    ebx = (esi >> 8) & 0xff;
                    eax = eax ^ keys[ebx + 0x212];
                    ebx = esi & 0xff;
                    eax = eax + keys[ebx + 0x312];

                    eax = eax ^ keys[15];
                    eax = ecx ^ eax;
                    ecx = eax >> 0x18;
                    ebx = (eax >> 0x10) & 0xFF;
                    ecx = keys[ecx + 0x12] + keys[ebx + 0x112];
                    ebx = (eax >> 8) & 0xff;
                    ecx = ecx ^ keys[ebx + 0x212];
                    ebx = eax & 0xff;
                    ecx = ecx + keys[ebx + 0x312];

                    ecx = ecx ^ keys[16];
                    ecx = ecx ^ esi;
                    esi = keys[17];
                    esi = esi ^ eax;
                    keys[(ou / 4) + (edi / 4)] = esi;
                    keys[(ou / 4) + (edi / 4) + 1] = ecx;
                    edi = edi + 8;
                }
                ou = ou + 0x400;
            }
        }

    /*
    * byte[] Decrypt(byte[] ToEnd, int offset, int length)
    *  
    * Decrypts a byte stream using the Blue Burst Encryption Algorithm at the passed offset, with the requested length.
    * 
    * Returns a decoded version of the passed byte array.
    * 
    */
        public byte[] Decrypt(byte[] toDec, uint offset, uint length)
        {
            try
            {
                if (length % 8 != 0)
                {
                    throw new Exception("The length requested is not divisible by 8.");
                }

                var data = new byte[length];
                Buffer.BlockCopy(toDec, (int)offset, data, 0, (int)length);

                uint eax, ecx, edx, ebx, ebp, esi, edi, tmp;

                edx = 0;
                ecx = 0;
                eax = 0;

                while (edx < length)
                {
                    ebx = BitConverter.ToUInt32(data, (int) edx);
                    ebx = LE32(ebx);
                    ebx = ebx ^ keys[5];
                    ebp = ((keys[(ebx >> 0x18) + 0x12] + keys[((ebx >> 0x10) & 0xff) + 0x112])
                           ^ keys[((ebx >> 0x8) & 0xff) + 0x212]) + keys[(ebx & 0xff) + 0x312];
                    ebp = ebp ^ keys[4];
                    tmp = BitConverter.ToUInt32(data, (int) edx + 4);
                    ebp ^= LE32(tmp);
                    edi = ((keys[(ebp >> 0x18) + 0x12] + keys[((ebp >> 0x10) & 0xff) + 0x112])
                           ^ keys[((ebp >> 0x8) & 0xff) + 0x212]) + keys[(ebp & 0xff) + 0x312];
                    edi = edi ^ keys[3];
                    ebx = ebx ^ edi;
                    esi = ((keys[(ebx >> 0x18) + 0x12] + keys[((ebx >> 0x10) & 0xff) + 0x112])
                           ^ keys[((ebx >> 0x8) & 0xff) + 0x212]) + keys[(ebx & 0xff) + 0x312];
                    ebp = ebp ^ esi ^ keys[2];
                    edi = ((keys[(ebp >> 0x18) + 0x12] + keys[((ebp >> 0x10) & 0xff) + 0x112])
                           ^ keys[((ebp >> 0x8) & 0xff) + 0x212]) + keys[(ebp & 0xff) + 0x312];
                    edi = edi ^ keys[1];
                    ebp = ebp ^ keys[0];
                    ebx = ebx ^ edi;

                    BitConverter.GetBytes(LE32(ebp)).CopyTo(data, edx);
                    BitConverter.GetBytes(LE32(ebx)).CopyTo(data, edx + 4);

                    edx = edx + 8;
                }
                return (data);
            }
            catch (Exception e)
            {
                throw new PSOEncryptionException("The packet decryptor encountered an error: " + e.Message);
            }
    }

        private void InitKeys(byte[] data)
        {
            uint x;
            for (x = 0; x < 48; x += 3)
            {
                data[x] ^= 0x19;
                data[x + 1] ^= 0x16;
                data[x + 2] ^= 0x18;
            }
        }


        /*
         * byte[] Encrypt(byte[] ToEnd, int offset, int length)
         * 
         * Encrypts a byte stream using the Blue Burst Encryption Algorithm.
         * 
         * Returns an encoded version of the passed byte array.
         * 
         */
        public byte[] Encrypt(byte[] ToEnc, int offset, int length)
        {
            try
            {
                if(length % 8 != 0)
                {
                    throw new Exception("The length requested is not divisible by 8.");
                }

                var data = new byte[length];

                Buffer.BlockCopy(ToEnc, offset, data, 0, length);

                uint eax, ecx, edx, ebx, ebp, esi, edi, tmp;

                edx = 0;

                ecx = 0;
                eax = 0;
                while (edx < length)
                {
                    ebx = BitConverter.ToUInt32(data, (int) edx);
                    ebx = LE32(ebx);
                    ebx = ebx ^ keys[0];
                    ebp = ((keys[(ebx >> 0x18) + 0x12] + keys[((ebx >> 0x10) & 0xff) + 0x112])
                           ^ keys[((ebx >> 0x8) & 0xff) + 0x212]) + keys[(ebx & 0xff) + 0x312];
                    ebp = ebp ^ keys[1];
                    tmp = BitConverter.ToUInt32(data, (int) edx + 4);
                    ebp ^= tmp;
                    edi = ((keys[(ebp >> 0x18) + 0x12] + keys[((ebp >> 0x10) & 0xff) + 0x112])
                           ^ keys[((ebp >> 0x8) & 0xff) + 0x212]) + keys[(ebp & 0xff) + 0x312];
                    edi = edi ^ keys[2];
                    ebx = ebx ^ edi;
                    esi = ((keys[(ebx >> 0x18) + 0x12] + keys[((ebx >> 0x10) & 0xff) + 0x112])
                           ^ keys[((ebx >> 0x8) & 0xff) + 0x212]) + keys[(ebx & 0xff) + 0x312];
                    ebp = ebp ^ esi ^ keys[3];
                    edi = ((keys[(ebp >> 0x18) + 0x12] + keys[((ebp >> 0x10) & 0xff) + 0x112])
                           ^ keys[((ebp >> 0x8) & 0xff) + 0x212]) + keys[(ebp & 0xff) + 0x312];
                    edi = edi ^ keys[4];
                    ebp = ebp ^ keys[5];
                    ebx = ebx ^ edi;

                    BitConverter.GetBytes(LE32(ebp)).CopyTo(data, edx);
                    BitConverter.GetBytes(LE32(ebx)).CopyTo(data, edx + 4);

                    edx = edx + 8;
                }
                return (data);
            }
            catch(Exception e)
            {
                throw new PSOEncryptionException("The packet encryptor encountered an error: " + e.Message);
            }
        }

        /*
         * uint LE32(uint x)
         * 
         * Little Endian -> Big Endian conversion code for unsigned integers, ported from Sylverant. Original copyright Lawrence Siebald, 2016.
         * 
         * This code may not matter as BitConverter probably already accounts for Endian-ness when performing operations.
         * 
         * TODO: Look into this and make a decision on whether or not this needs to be kept.
         */
        private uint LE32(uint x)
        {
            if (!BitConverter.IsLittleEndian)
            {
                x = (((x >> 24) & 0x00FF) |
                 ((x >> 8) & 0xFF00) | 
                 ((x & 0xFF00) << 8) | 
                 ((x & 0x00FF) << 24)); 
                return x;
            }
            return x;
        }

    }
}
