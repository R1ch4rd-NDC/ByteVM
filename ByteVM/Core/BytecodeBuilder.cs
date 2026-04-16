using System;
using System.Collections.Generic;
using ByteVM.Runtime;

namespace ByteVM.Core
{
    // Builds a flat byte[] of VM bytecode.
    // If an OpcodeShuffler is provided, every opcode byte goes through it before
    // being written, so the raw buffer already contains the shuffled form.
    internal class BytecodeBuilder
    {
        private readonly List<byte>     _buf      = new List<byte>(256);
        private readonly OpcodeShuffler _shuffler;

        public int Position => _buf.Count;

        public BytecodeBuilder(OpcodeShuffler shuffler = null)
        {
            _shuffler = shuffler;
        }

        public void Emit(VMOpCode op)
        {
            _buf.Add(_shuffler != null ? _shuffler.Shuffle(op) : (byte)op);
        }

        public void EmitByte(byte b)   => _buf.Add(b);
        public void EmitBytes(byte[] b) => _buf.AddRange(b);

        public void EmitU16(ushort v)
        {
            _buf.Add((byte)(v & 0xFF));
            _buf.Add((byte)((v >> 8) & 0xFF));
        }

        public void EmitI32(int v)
        {
            _buf.Add((byte)(v         & 0xFF));
            _buf.Add((byte)((v >>  8) & 0xFF));
            _buf.Add((byte)((v >> 16) & 0xFF));
            _buf.Add((byte)((v >> 24) & 0xFF));
        }

        public void EmitI64(long v)
        {
            EmitI32((int)(v & 0xFFFFFFFFL));
            EmitI32((int)((v >> 32) & 0xFFFFFFFFL));
        }

        public void EmitR32(float v)   => _buf.AddRange(BitConverter.GetBytes(v));
        public void EmitR64(double v)  => _buf.AddRange(BitConverter.GetBytes(v));

        // Emits a (shuffled) branch opcode followed by four zero bytes as a
        // placeholder for the target offset. Returns the index of that placeholder
        // so PatchI32 can fill it in once the target's position is known.
        public int EmitBranchSlot(VMOpCode op)
        {
            _buf.Add(_shuffler != null ? _shuffler.Shuffle(op) : (byte)op);
            int patchOffset = _buf.Count;
            _buf.Add(0); _buf.Add(0); _buf.Add(0); _buf.Add(0);
            return patchOffset;
        }

        public void PatchI32(int slotOffset, int value)
        {
            _buf[slotOffset]     = (byte)(value         & 0xFF);
            _buf[slotOffset + 1] = (byte)((value >>  8) & 0xFF);
            _buf[slotOffset + 2] = (byte)((value >> 16) & 0xFF);
            _buf[slotOffset + 3] = (byte)((value >> 24) & 0xFF);
        }

        public byte[] ToArray() => _buf.ToArray();
    }
}
