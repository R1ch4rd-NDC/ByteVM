namespace ByteVM.Runtime
{
    public enum VMOpCode : byte
    {
        Nop     = 0,
        Dup     = 1,
        Pop     = 2,

        // Args and locals use a 2-byte index as operand, which gives room for
        // up to 65535 parameters or local slots — more than enough in practice.
        Ldarg   = 10,
        Starg   = 11,
        Ldloc   = 12,
        Stloc   = 13,

        // Inline constants. Strings are stored as a 4-byte length followed by
        // that many UTF-8 bytes, since string tokens don't survive relocation.
        Ldc_I4  = 20,
        Ldc_I8  = 21,
        Ldc_R4  = 22,
        Ldc_R8  = 23,
        Ldc_Str = 24,
        Ldnull  = 25,

        // Standard binary arithmetic; the interpreter picks int/long/float/double
        // based on what's on the stack, mirroring CIL's numeric promotion rules.
        Add     = 30,
        Sub     = 31,
        Mul     = 32,
        Div     = 33,
        Rem     = 34,
        Neg     = 35,

        And     = 40,
        Or      = 41,
        Xor     = 42,
        Not     = 43,
        Shl     = 44,
        Shr     = 45,
        Shr_Un  = 46,   // logical (unsigned) right shift

        // Each comparison pops two values and pushes 0 or 1.
        Ceq     = 50,
        Cgt     = 51,
        Clt     = 52,
        Cgt_Un  = 53,   // unsigned / unordered
        Clt_Un  = 54,

        Conv_I1 = 60,
        Conv_I2 = 61,
        Conv_I4 = 62,
        Conv_I8 = 63,
        Conv_U1 = 64,
        Conv_U2 = 65,
        Conv_U4 = 66,
        Conv_U8 = 67,
        Conv_R4 = 68,
        Conv_R8 = 69,

        // All branches carry a 4-byte absolute bytecode offset as operand.
        // Absolute offsets keep the branch-patching logic simple: you just
        // write the target position once it's known, no relative math needed.
        Br      = 80,
        Brtrue  = 81,
        Brfalse = 82,
        Beq     = 83,
        Bge     = 84,
        Bgt     = 85,
        Ble     = 86,
        Blt     = 87,
        Bne_Un  = 88,
        Bge_Un  = 89,
        Bgt_Un  = 90,
        Ble_Un  = 91,
        Blt_Un  = 92,

        Ret_Val  = 100,  // return with a value
        Ret_Void = 101,  // return nothing
        Throw    = 102,

        // Calls carry a 4-byte index into the MethodBase[] table that was built
        // at obfuscation time and stored alongside the bytecode.
        Call     = 110,
        Callvirt = 111,
        Newobj   = 112,

        // Same idea for fields — 4-byte index into the FieldInfo[] table.
        Ldfld   = 120,
        Stfld   = 121,
        Ldsfld  = 122,
        Stsfld  = 123,

        // Type ops carry a 4-byte index into the Type[] table.
        Box       = 130,
        Unbox_Any = 131,
        Castclass = 132,
        Isinst    = 133,
        Initobj   = 134,
        Newarr    = 135,

        Ldlen     = 140,
        Ldelem    = 141,
        Stelem    = 142,

        // Leave's operand is the absolute bytecode offset of the instruction
        // right after the try/catch block. The interpreter handles the "run all
        // pending finally blocks before jumping" part at runtime.
        Leave      = 150,
        Endfinally = 151,  // marks the end of a finally or fault block
        Rethrow    = 152,  // re-throws the exception currently being handled
    }
}
