using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using PSOCrypt.Exceptions;

namespace PSOCrypt
{

    /*   Phantasy Star Online: Gamecube Encryption Library
     * 
     *   First written by Fuzziqer Software in C and ported to C# by TauAkiou.
     *   Code primarily adapted from the Tethealla (Larry Chatman Jr.) + Sylverant (Lawrence Siebald) projects.
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
     *   This library object supports Phantasy Star Online v2 for the Nintendo Gamecube.
     *  
     *   IMPORTANT NOTES:
     *  
     *   This encryption algorithm is designed to work on 4 byte blocks of data at a time. It is up to the developer to ensure that the length of
     *   streams passed to the encryption object are divisible by 4. The encryption algorithm will throw an exception if the
     *   stream is not properly divisible by 4.
     *  
     *   keyposition is advanced on both the client and server side for each uint crypted by the engine. The client will typically only crypt
     *   however many bytes the command sent (ushort, first two bytes of an incoming packet) plus any bytes required to make the command stream
     *   size divisible by 4. If the server crypts too many or too few bytes, the encryption will fall out of sync and the next packet recieved/sent
     *   will crypt to garbage. Therefore, it is the developer's responsibility to keep the encryption in sync by only crypting the exact number of bytes
     *   expected by the other side of the connection.
     *  
     *   The Gamecube encryption is experimental and has not been tested at all. It is probably broken.
     */

    public sealed class PsoEncryptionGC
    {
        private uint[] keys = new uint[522];
        private ushort keyposition;
        private const ushort KEYEND = 521; // Ending index.
        public uint Seed { get; private set; }
        public byte[] SeedBytes { get
            {
                return BitConverter.GetBytes(Seed);
            } }
        

        public PsoEncryptionGC()
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var seedbyt = new byte[4];
                rng.GetBytes(SeedBytes);
                Seed = BitConverter.ToUInt32(seedbyt, 0);
                Create(Seed);
            } 
        }

        private void MixKeys()
        {
            uint r0, r4, r5, r6, r7;
            // r5, r6, r7 are position values

            keyposition = 0;

            r5 = 0;
            r6 = 489;
            r7 = 0;

            while(r6 != KEYEND)
            {
                r0 = keys[r6];
                r6++;
                r4 = keys[r5];
                r0 ^= r4;
                keys[r5] = r0;
                r5++;
            }

            while(r5 != KEYEND)
            {
                r0 = keys[r7];
                r7++;
                r4 = keys[r5];
                r0 ^= r4;
                keys[r5] = r0;
                r5++;
            }
        }

        private uint NextKey()
        {
            keyposition++;
            if(keyposition == KEYEND)
            {
                MixKeys();
            }
            return keys[keyposition];
        }

        public byte[] Crypt(byte[] buffer)
        {
            try
            {
                if (buffer.Length % 4 != 0)
                {
                    throw new Exception("Buffer length is not divisible by 4.");
                }
                using (var ms = new MemoryStream())
                {
                    uint startpos, endpos, tmp;

                    startpos = 0;
                    endpos = (uint)buffer.Length;

                    while (startpos < endpos)
                    {
                        tmp = NextKey();
                        var store = BitConverter.ToUInt32(buffer, (int)startpos);
                        store = store ^ tmp;

                        ms.Write(BitConverter.GetBytes(store), 0, sizeof(uint));
                    }
                    return ms.ToArray();
                }
            }
            catch (Exception e)
            {
                throw new PsoEncryptionException("The packet decryptor encountered an error: " + e.Message);
            }
        }

        private void Create(uint encseed) 
        {
            uint x, y, basekey;

            // Position values (pointers):
            uint source1, source2, source3;

            basekey = 0;
            Seed = encseed;

            keyposition = 0;

            for(x = 0; x <= 16; x++)
            {
                for(y = 0; y < 32; y++)
                {
                    encseed = Seed * 0x5D588B65;
                    basekey = basekey >> 1;
                    encseed++;
                    if((encseed & 0x80000000) != 0)
                    {
                        basekey = basekey | 0x7FFFFFFF;
                    }
                }
                keys[keyposition] = (ushort)basekey;
                keyposition = (ushort)(keyposition + 4);
            }

            source1 = 0;
            source2 = 1;

            keyposition = (ushort)(keyposition - 4);
            keys[keyposition] = ((keys[0] >> 9)) ^ (keys[keyposition] << 23) ^ keys[15];
            source3 = keyposition;

            // Now do the rest of the work.

            while(keyposition != keys.Length - 1)
            {
                keys[keyposition] = (keys[source3] ^ (((keys[source1] << 23) & 0xFF800000) ^ ((keys[source2] >> 9) & 0x007FFFFF)));
                keyposition = (ushort)(keyposition + 4);
                source1 = (ushort)(source1 + 4);
                source2 = (ushort)(source2 + 4);
                source3 = (ushort)(source3 + 4);
            }
            MixKeys();
            MixKeys();
            MixKeys();
            keyposition = 520;

 
        }
    }
}
