using System;
using System.Collections.Generic;
using ByteVM.Runtime;

namespace ByteVM.Core
{
    // Builds a random bijective mapping between VMOpCode values and the bytes
    // that actually get written into the bytecode on a given build.
    //
    // At obfuscation time: Shuffle(op) gives the byte to emit.
    // At runtime: decodeTable[shuffledByte] gives the original VMOpCode.
    //
    // Because the mapping is random every build, two protected assemblies built
    // from the same source will have completely different bytecode streams even
    // before XOR encryption is applied.
    internal class OpcodeShuffler
    {
        private readonly byte[] _shuffle = new byte[256]; // VMOpCode → shuffled byte
        private readonly byte[] _decode  = new byte[256]; // shuffled byte → VMOpCode

        public OpcodeShuffler()
        {
            // Fisher-Yates over a pool of 0..255 so every byte gets used exactly once.
            // Using a removal pool rather than a swap avoids having to undo assignments
            // when building the inverse table.
            var pool = new List<byte>(256);
            for (int i = 0; i < 256; i++) pool.Add((byte)i);

            var rng = new Random();
            for (int i = 0; i < 256; i++)
            {
                int j = rng.Next(pool.Count);
                byte shuffled = pool[j];
                pool.RemoveAt(j);

                _shuffle[i] = shuffled;
                _decode[shuffled] = (byte)i;
            }
        }

        public byte Shuffle(VMOpCode op) => _shuffle[(byte)op];

        // Returns a copy — callers store this in the protected assembly.
        // The original stays here only for the duration of the obfuscation pass.
        public byte[] DecodeTable => (byte[])_decode.Clone();
    }
}
