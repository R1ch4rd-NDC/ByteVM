using System;
using System.Collections.Generic;
using System.Text;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using ByteVM.Runtime;

namespace ByteVM.Core
{
    // Translates one CIL method body into VM bytecode + a binary exception-handler table.
    // The three shared tables (methods, fields, types) are passed in and grown here;
    // RuntimeInjector reads them back to populate __VMData__ at injection time.
    internal class MethodVirtualizer
    {
        private readonly List<IMethod>       _methodTable;
        private readonly List<IField>        _fieldTable;
        private readonly List<ITypeDefOrRef> _typeTable;
        private readonly OpcodeShuffler      _shuffler;

        public MethodVirtualizer(
            List<IMethod>       methodTable,
            List<IField>        fieldTable,
            List<ITypeDefOrRef> typeTable,
            OpcodeShuffler      shuffler = null)
        {
            _methodTable = methodTable;
            _fieldTable  = fieldTable;
            _typeTable   = typeTable;
            _shuffler    = shuffler;
        }

        // Returns (bytecode, handlerTable, localsCount).
        // handlerTable is empty when the method has no exception handlers.
        public (byte[] bytecode, byte[] handlerTable, int localsCount) Virtualize(MethodDef method)
        {
            var body    = method.Body;
            bool isVoid = method.ReturnType.ElementType == ElementType.Void;

            // SimplifyMacros rewrites things like ldarg.0 → ldarg 0 and ldc.i4.s → ldc.i4
            // so we don't have to handle the short forms below.
            body.SimplifyMacros(method.Parameters);

            // Filter handlers require executing a user-supplied block to decide whether
            // to catch — we'd need a second interpreter stack for that, skip for now.
            if (body.HasExceptionHandlers)
            {
                foreach (var eh in body.ExceptionHandlers)
                {
                    if (eh.HandlerType == ExceptionHandlerType.Filter)
                        throw new NotSupportedException("Filter exception handlers are not supported.");
                }
            }

            var builder       = new BytecodeBuilder(_shuffler);
            var instrs        = body.Instructions;
            var instrVmOffset = new Dictionary<Instruction, int>(instrs.Count);
            var branches      = new List<(int slot, Instruction target)>();

            for (int i = 0; i < instrs.Count; i++)
            {
                var ins = instrs[i];
                instrVmOffset[ins] = builder.Position;
                EmitInstruction(ins, builder, branches, isVoid);
            }

            // Second pass: now that every instruction has a VM offset, fill in the
            // branch target placeholders that were left as zeros in the first pass.
            foreach (var (slot, target) in branches)
            {
                if (!instrVmOffset.TryGetValue(target, out int offset))
                    throw new InvalidOperationException(
                        $"[VM] Branch target not found in method '{method.Name}'.");
                builder.PatchI32(slot, offset);
            }

            int totalLength = builder.Position;
            byte[] handlerTable = SerializeHandlers(body, instrVmOffset, totalLength);

            return (builder.ToArray(), handlerTable, body.Variables.Count);
        }

        private void EmitInstruction(
            Instruction ins,
            BytecodeBuilder builder,
            List<(int slot, Instruction target)> branches,
            bool methodIsVoid)
        {
            switch (ins.OpCode.Code)
            {
                case Code.Nop: builder.Emit(VMOpCode.Nop); break;
                case Code.Dup: builder.Emit(VMOpCode.Dup); break;
                case Code.Pop: builder.Emit(VMOpCode.Pop); break;

                case Code.Ldarg: case Code.Ldarg_S:
                    builder.Emit(VMOpCode.Ldarg);
                    builder.EmitU16((ushort)((Parameter)ins.Operand).Index);
                    break;

                case Code.Starg: case Code.Starg_S:
                    builder.Emit(VMOpCode.Starg);
                    builder.EmitU16((ushort)((Parameter)ins.Operand).Index);
                    break;

                case Code.Ldloc: case Code.Ldloc_S:
                    builder.Emit(VMOpCode.Ldloc);
                    builder.EmitU16((ushort)((Local)ins.Operand).Index);
                    break;

                case Code.Stloc: case Code.Stloc_S:
                    builder.Emit(VMOpCode.Stloc);
                    builder.EmitU16((ushort)((Local)ins.Operand).Index);
                    break;

                case Code.Ldc_I4: case Code.Ldc_I4_S:
                    builder.Emit(VMOpCode.Ldc_I4);
                    builder.EmitI32(ins.GetLdcI4Value());
                    break;

                case Code.Ldc_I8:
                    builder.Emit(VMOpCode.Ldc_I8);
                    builder.EmitI64((long)ins.Operand);
                    break;

                case Code.Ldc_R4:
                    builder.Emit(VMOpCode.Ldc_R4);
                    builder.EmitR32((float)ins.Operand);
                    break;

                case Code.Ldc_R8:
                    builder.Emit(VMOpCode.Ldc_R8);
                    builder.EmitR64((double)ins.Operand);
                    break;

                case Code.Ldstr:
                {
                    byte[] bytes = Encoding.UTF8.GetBytes((string)ins.Operand);
                    builder.Emit(VMOpCode.Ldc_Str);
                    builder.EmitI32(bytes.Length);
                    builder.EmitBytes(bytes);
                    break;
                }

                case Code.Ldnull: builder.Emit(VMOpCode.Ldnull); break;

                case Code.Add: case Code.Add_Ovf: case Code.Add_Ovf_Un: builder.Emit(VMOpCode.Add); break;
                case Code.Sub: case Code.Sub_Ovf: case Code.Sub_Ovf_Un: builder.Emit(VMOpCode.Sub); break;
                case Code.Mul: case Code.Mul_Ovf: case Code.Mul_Ovf_Un: builder.Emit(VMOpCode.Mul); break;
                case Code.Div: case Code.Div_Un:  builder.Emit(VMOpCode.Div); break;
                case Code.Rem: case Code.Rem_Un:  builder.Emit(VMOpCode.Rem); break;
                case Code.Neg: builder.Emit(VMOpCode.Neg); break;

                case Code.And:    builder.Emit(VMOpCode.And);    break;
                case Code.Or:     builder.Emit(VMOpCode.Or);     break;
                case Code.Xor:    builder.Emit(VMOpCode.Xor);    break;
                case Code.Not:    builder.Emit(VMOpCode.Not);    break;
                case Code.Shl:    builder.Emit(VMOpCode.Shl);    break;
                case Code.Shr:    builder.Emit(VMOpCode.Shr);    break;
                case Code.Shr_Un: builder.Emit(VMOpCode.Shr_Un); break;

                case Code.Ceq:    builder.Emit(VMOpCode.Ceq);    break;
                case Code.Cgt:    builder.Emit(VMOpCode.Cgt);    break;
                case Code.Clt:    builder.Emit(VMOpCode.Clt);    break;
                case Code.Cgt_Un: builder.Emit(VMOpCode.Cgt_Un); break;
                case Code.Clt_Un: builder.Emit(VMOpCode.Clt_Un); break;

                case Code.Conv_I1: case Code.Conv_Ovf_I1: case Code.Conv_Ovf_I1_Un: builder.Emit(VMOpCode.Conv_I1); break;
                case Code.Conv_I2: case Code.Conv_Ovf_I2: case Code.Conv_Ovf_I2_Un: builder.Emit(VMOpCode.Conv_I2); break;
                case Code.Conv_I4: case Code.Conv_Ovf_I4: case Code.Conv_Ovf_I4_Un: builder.Emit(VMOpCode.Conv_I4); break;
                case Code.Conv_I8: case Code.Conv_Ovf_I8: case Code.Conv_Ovf_I8_Un: builder.Emit(VMOpCode.Conv_I8); break;
                case Code.Conv_U1: case Code.Conv_Ovf_U1: case Code.Conv_Ovf_U1_Un: builder.Emit(VMOpCode.Conv_U1); break;
                case Code.Conv_U2: case Code.Conv_Ovf_U2: case Code.Conv_Ovf_U2_Un: builder.Emit(VMOpCode.Conv_U2); break;
                case Code.Conv_U4: case Code.Conv_Ovf_U4: case Code.Conv_Ovf_U4_Un: builder.Emit(VMOpCode.Conv_U4); break;
                case Code.Conv_U8: case Code.Conv_Ovf_U8: case Code.Conv_Ovf_U8_Un: builder.Emit(VMOpCode.Conv_U8); break;
                case Code.Conv_R4: builder.Emit(VMOpCode.Conv_R4); break;
                case Code.Conv_R8: builder.Emit(VMOpCode.Conv_R8); break;
                // native int → treat as 64-bit, close enough for managed code
                case Code.Conv_I: case Code.Conv_Ovf_I: case Code.Conv_Ovf_I_Un: builder.Emit(VMOpCode.Conv_I8); break;
                case Code.Conv_U: case Code.Conv_Ovf_U: case Code.Conv_Ovf_U_Un: builder.Emit(VMOpCode.Conv_U8); break;

                case Code.Br:      case Code.Br_S:      EmitBranch(VMOpCode.Br,      ins, builder, branches); break;
                case Code.Brtrue:  case Code.Brtrue_S:  EmitBranch(VMOpCode.Brtrue,  ins, builder, branches); break;
                case Code.Brfalse: case Code.Brfalse_S: EmitBranch(VMOpCode.Brfalse, ins, builder, branches); break;
                case Code.Beq:     case Code.Beq_S:     EmitBranch(VMOpCode.Beq,     ins, builder, branches); break;
                case Code.Bge:     case Code.Bge_S:     EmitBranch(VMOpCode.Bge,     ins, builder, branches); break;
                case Code.Bgt:     case Code.Bgt_S:     EmitBranch(VMOpCode.Bgt,     ins, builder, branches); break;
                case Code.Ble:     case Code.Ble_S:     EmitBranch(VMOpCode.Ble,     ins, builder, branches); break;
                case Code.Blt:     case Code.Blt_S:     EmitBranch(VMOpCode.Blt,     ins, builder, branches); break;
                case Code.Bne_Un:  case Code.Bne_Un_S:  EmitBranch(VMOpCode.Bne_Un,  ins, builder, branches); break;
                case Code.Bge_Un:  case Code.Bge_Un_S:  EmitBranch(VMOpCode.Bge_Un,  ins, builder, branches); break;
                case Code.Bgt_Un:  case Code.Bgt_Un_S:  EmitBranch(VMOpCode.Bgt_Un,  ins, builder, branches); break;
                case Code.Ble_Un:  case Code.Ble_Un_S:  EmitBranch(VMOpCode.Ble_Un,  ins, builder, branches); break;
                case Code.Blt_Un:  case Code.Blt_Un_S:  EmitBranch(VMOpCode.Blt_Un,  ins, builder, branches); break;

                // Leave behaves like a branch at the VM level — the interpreter handles
                // the "run finallys before jumping" part at runtime.
                case Code.Leave: case Code.Leave_S:
                    EmitBranch(VMOpCode.Leave, ins, builder, branches);
                    break;

                case Code.Endfinally:
                    builder.Emit(VMOpCode.Endfinally);
                    break;

                case Code.Endfilter:
                    throw new NotSupportedException("Endfilter is not supported.");

                case Code.Rethrow:
                    builder.Emit(VMOpCode.Rethrow);
                    break;

                case Code.Ret:
                    builder.Emit(methodIsVoid ? VMOpCode.Ret_Void : VMOpCode.Ret_Val);
                    break;

                case Code.Throw:
                    builder.Emit(VMOpCode.Throw);
                    break;

                case Code.Call:
                    builder.Emit(VMOpCode.Call);
                    builder.EmitI32(GetOrAddMethod((IMethod)ins.Operand));
                    break;

                case Code.Callvirt:
                    builder.Emit(VMOpCode.Callvirt);
                    builder.EmitI32(GetOrAddMethod((IMethod)ins.Operand));
                    break;

                case Code.Newobj:
                    builder.Emit(VMOpCode.Newobj);
                    builder.EmitI32(GetOrAddMethod((IMethod)ins.Operand));
                    break;

                case Code.Ldfld:  builder.Emit(VMOpCode.Ldfld);  builder.EmitI32(GetOrAddField((IField)ins.Operand)); break;
                case Code.Stfld:  builder.Emit(VMOpCode.Stfld);  builder.EmitI32(GetOrAddField((IField)ins.Operand)); break;
                case Code.Ldsfld: builder.Emit(VMOpCode.Ldsfld); builder.EmitI32(GetOrAddField((IField)ins.Operand)); break;
                case Code.Stsfld: builder.Emit(VMOpCode.Stsfld); builder.EmitI32(GetOrAddField((IField)ins.Operand)); break;

                case Code.Box:       builder.Emit(VMOpCode.Box);       builder.EmitI32(GetOrAddType((ITypeDefOrRef)ins.Operand)); break;
                case Code.Unbox_Any: builder.Emit(VMOpCode.Unbox_Any); builder.EmitI32(GetOrAddType((ITypeDefOrRef)ins.Operand)); break;
                case Code.Castclass: builder.Emit(VMOpCode.Castclass); builder.EmitI32(GetOrAddType((ITypeDefOrRef)ins.Operand)); break;
                case Code.Isinst:    builder.Emit(VMOpCode.Isinst);    builder.EmitI32(GetOrAddType((ITypeDefOrRef)ins.Operand)); break;
                case Code.Initobj:   builder.Emit(VMOpCode.Initobj);   builder.EmitI32(GetOrAddType((ITypeDefOrRef)ins.Operand)); break;
                case Code.Newarr:    builder.Emit(VMOpCode.Newarr);    builder.EmitI32(GetOrAddType((ITypeDefOrRef)ins.Operand)); break;

                case Code.Ldlen: builder.Emit(VMOpCode.Ldlen); break;

                case Code.Ldelem:
                case Code.Ldelem_I:  case Code.Ldelem_I1: case Code.Ldelem_I2:
                case Code.Ldelem_I4: case Code.Ldelem_I8: case Code.Ldelem_U1:
                case Code.Ldelem_U2: case Code.Ldelem_U4: case Code.Ldelem_R4:
                case Code.Ldelem_R8: case Code.Ldelem_Ref:
                    builder.Emit(VMOpCode.Ldelem);
                    break;

                case Code.Stelem:
                case Code.Stelem_I:  case Code.Stelem_I1: case Code.Stelem_I2:
                case Code.Stelem_I4: case Code.Stelem_I8: case Code.Stelem_R4:
                case Code.Stelem_R8: case Code.Stelem_Ref:
                    builder.Emit(VMOpCode.Stelem);
                    break;

                default:
                    throw new NotSupportedException(
                        $"[VM] Unsupported CIL opcode: {ins.OpCode.Name}");
            }
        }

        // Serializes body.ExceptionHandlers into a flat byte[].
        //
        // Layout:  [int32 count]  followed by count records of 6 × int32:
        //   type      (0=catch, 1=finally, 2=fault)
        //   tryStart  (inclusive VM offset)
        //   tryEnd    (exclusive — points to first byte after the try block)
        //   hdrStart
        //   hdrEnd    (exclusive, or totalLength if the handler reaches end of method)
        //   typeIdx   (index into the type table for catch; -1 for finally/fault)
        //
        // TryEnd and HandlerEnd in dnlib are already the instruction AFTER the block,
        // so instrVmOffset[eh.TryEnd] gives the correct exclusive boundary directly.
        private byte[] SerializeHandlers(
            CilBody body,
            Dictionary<Instruction, int> instrVmOffset,
            int totalLength)
        {
            if (!body.HasExceptionHandlers) return new byte[0];

            var entries = new List<(int type, int tryStart, int tryEnd,
                                    int hdrStart, int hdrEnd, int typeIdx)>();

            foreach (var eh in body.ExceptionHandlers)
            {
                int type;
                int typeIdx = -1;

                switch (eh.HandlerType)
                {
                    case ExceptionHandlerType.Catch:
                        type    = 0;
                        typeIdx = GetOrAddType(eh.CatchType);
                        break;
                    case ExceptionHandlerType.Finally: type = 1; break;
                    case ExceptionHandlerType.Fault:   type = 2; break;
                    default: continue;
                }

                if (!instrVmOffset.TryGetValue(eh.TryStart, out int tryStart))
                    throw new InvalidOperationException("[VM] Cannot resolve TryStart VM offset.");

                int tryEnd   = eh.TryEnd     != null ? instrVmOffset[eh.TryEnd]     : totalLength;
                int hdrStart = instrVmOffset[eh.HandlerStart];
                int hdrEnd   = eh.HandlerEnd != null ? instrVmOffset[eh.HandlerEnd] : totalLength;

                entries.Add((type, tryStart, tryEnd, hdrStart, hdrEnd, typeIdx));
            }

            if (entries.Count == 0) return new byte[0];

            var buf = new List<byte>(4 + entries.Count * 24);
            WriteI32(buf, entries.Count);
            foreach (var (type, tryStart, tryEnd, hdrStart, hdrEnd, typeIdx) in entries)
            {
                WriteI32(buf, type);
                WriteI32(buf, tryStart);
                WriteI32(buf, tryEnd);
                WriteI32(buf, hdrStart);
                WriteI32(buf, hdrEnd);
                WriteI32(buf, typeIdx);
            }
            return buf.ToArray();
        }

        private static void WriteI32(List<byte> buf, int v)
        {
            buf.Add((byte)(v         & 0xFF));
            buf.Add((byte)((v >>  8) & 0xFF));
            buf.Add((byte)((v >> 16) & 0xFF));
            buf.Add((byte)((v >> 24) & 0xFF));
        }

        private static void EmitBranch(
            VMOpCode vmOp,
            Instruction ins,
            BytecodeBuilder builder,
            List<(int slot, Instruction target)> branches)
        {
            int slot = builder.EmitBranchSlot(vmOp);
            branches.Add((slot, (Instruction)ins.Operand));
        }

        // GetOrAdd helpers — deduplicate entries across methods so the runtime
        // tables stay small when many methods reference the same member.
        private int GetOrAddMethod(IMethod m)
        {
            string key = m.FullName;
            for (int i = 0; i < _methodTable.Count; i++)
                if (_methodTable[i].FullName == key) return i;
            _methodTable.Add(m);
            return _methodTable.Count - 1;
        }

        private int GetOrAddField(IField f)
        {
            string key = f.FullName;
            for (int i = 0; i < _fieldTable.Count; i++)
                if (_fieldTable[i].FullName == key) return i;
            _fieldTable.Add(f);
            return _fieldTable.Count - 1;
        }

        private int GetOrAddType(ITypeDefOrRef t)
        {
            string key = t.FullName;
            for (int i = 0; i < _typeTable.Count; i++)
                if (_typeTable[i].FullName == key) return i;
            _typeTable.Add(t);
            return _typeTable.Count - 1;
        }
    }
}
