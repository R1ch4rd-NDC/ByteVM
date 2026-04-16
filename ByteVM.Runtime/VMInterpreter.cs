using System;
using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;

namespace ByteVM.Runtime
{
    public static class VMInterpreter
    {
        // One entry per method, keyed by the reference identity of the static encrypted-code
        // array. Because each protected method has its own static field holding that array,
        // the reference never changes between calls, so this effectively caches decryption
        // for the lifetime of the process without any explicit invalidation logic.
        private static readonly ConcurrentDictionary<int, byte[]> _decryptCache =
            new ConcurrentDictionary<int, byte[]>();

        // Mirrors the binary layout written by MethodVirtualizer.SerializeHandlers:
        // [count:i32] then count×[type, tryStart, tryEnd, handlerStart, handlerEnd, catchTypeIdx].
        private struct HandlerEntry
        {
            public int Type;          // 0 = catch, 1 = finally, 2 = fault
            public int TryStart;      // first VM offset inside the try region (inclusive)
            public int TryEnd;        // first VM offset outside it (exclusive)
            public int HandlerStart;  // where the handler body begins
            public int HandlerEnd;    // where it ends (exclusive)
            public int CatchTypeIdx;  // index into Type[]; -1 for finally/fault
        }

        public static object Execute(
            byte[]       encryptedCode,
            int          localsCount,
            object[]     args,
            byte[]       keyA,         // bytes 0-7 of the XOR key, stored as-is
            byte[]       keyB,         // bytes 8-15, each XOR'd with hashA at storage time
            byte[]       decodeTable,  // 256-byte shuffle-decode table
            byte[]       handlerTable, // serialized exception handler entries (may be empty)
            MethodBase[] methods,
            FieldInfo[]  fields,
            Type[]       types)
        {
            // Reconstruct the full 16-byte key. KeyB was stored as keyB[i] = original[8+i] ^ hashA,
            // where hashA is just the XOR of all bytes in KeyA. Reverse that now.
            byte hashA = 0;
            for (int j = 0; j < keyA.Length; j++) hashA ^= keyA[j];

            byte[] fullKey = new byte[16];
            Array.Copy(keyA, fullKey, 8);
            for (int j = 0; j < keyB.Length; j++)
                fullKey[8 + j] = (byte)(keyB[j] ^ hashA);

            // Decrypt once and cache. RuntimeHelpers.GetHashCode gives us the object identity
            // hash, which is stable for the lifetime of the static array.
            int cacheKey = RuntimeHelpers.GetHashCode(encryptedCode);
            byte[] code;
            if (!_decryptCache.TryGetValue(cacheKey, out code))
            {
                var plain = new byte[encryptedCode.Length];
                for (int j = 0; j < plain.Length; j++)
                    plain[j] = (byte)(encryptedCode[j] ^ fullKey[j % fullKey.Length]);
                code = _decryptCache.GetOrAdd(cacheKey, plain);
            }

            HandlerEntry[] handlers = ParseHandlerTable(handlerTable);

            var stack  = new object[512];
            int sp     = 0;
            var locals = new object[localsCount];
            int ip     = 0;

            // Exception dispatch state. currentException is non-null while we are
            // unwinding — either searching for a catch or running finally blocks
            // before re-throwing. leaveTarget/pendingFinallys track Leave chains.
            Exception  currentException  = null;
            int        currentHandlerIdx = -1;
            int        leaveTarget       = -1;
            int[]      pendingFinallys   = null;
            int        pendingFinallyPos = 0;

            while (true)
            {
                var op = (VMOpCode)decodeTable[code[ip++]];
                switch (op)
                {
                    case VMOpCode.Nop: break;

                    case VMOpCode.Dup:
                        stack[sp] = stack[sp - 1];
                        sp++;
                        break;

                    case VMOpCode.Pop:
                        sp--;
                        break;

                    case VMOpCode.Ldarg:
                        stack[sp++] = args[ReadU16(code, ref ip)];
                        break;

                    case VMOpCode.Starg:
                        args[ReadU16(code, ref ip)] = stack[--sp];
                        break;

                    case VMOpCode.Ldloc:
                        stack[sp++] = locals[ReadU16(code, ref ip)];
                        break;

                    case VMOpCode.Stloc:
                        locals[ReadU16(code, ref ip)] = stack[--sp];
                        break;

                    case VMOpCode.Ldc_I4:
                        stack[sp++] = ReadI32(code, ref ip);
                        break;

                    case VMOpCode.Ldc_I8:
                        stack[sp++] = ReadI64(code, ref ip);
                        break;

                    case VMOpCode.Ldc_R4:
                        stack[sp++] = ReadR32(code, ref ip);
                        break;

                    case VMOpCode.Ldc_R8:
                        stack[sp++] = ReadR64(code, ref ip);
                        break;

                    case VMOpCode.Ldc_Str:
                    {
                        int len = ReadI32(code, ref ip);
                        stack[sp++] = Encoding.UTF8.GetString(code, ip, len);
                        ip += len;
                        break;
                    }

                    case VMOpCode.Ldnull:
                        stack[sp++] = null;
                        break;

                    case VMOpCode.Add: { var b = stack[--sp]; var a = stack[--sp]; stack[sp++] = ArithAdd(a, b); break; }
                    case VMOpCode.Sub: { var b = stack[--sp]; var a = stack[--sp]; stack[sp++] = ArithSub(a, b); break; }
                    case VMOpCode.Mul: { var b = stack[--sp]; var a = stack[--sp]; stack[sp++] = ArithMul(a, b); break; }
                    case VMOpCode.Div: { var b = stack[--sp]; var a = stack[--sp]; stack[sp++] = ArithDiv(a, b); break; }
                    case VMOpCode.Rem: { var b = stack[--sp]; var a = stack[--sp]; stack[sp++] = ArithRem(a, b); break; }
                    case VMOpCode.Neg: stack[sp - 1] = ArithNeg(stack[sp - 1]); break;

                    case VMOpCode.And: { var b = stack[--sp]; var a = stack[--sp]; stack[sp++] = BitwiseAnd(a, b); break; }
                    case VMOpCode.Or:  { var b = stack[--sp]; var a = stack[--sp]; stack[sp++] = BitwiseOr (a, b); break; }
                    case VMOpCode.Xor: { var b = stack[--sp]; var a = stack[--sp]; stack[sp++] = BitwiseXor(a, b); break; }
                    case VMOpCode.Not: stack[sp - 1] = BitwiseNot(stack[sp - 1]); break;

                    case VMOpCode.Shl:
                    {
                        int shift = ToI32(stack[--sp]);
                        stack[sp - 1] = IsLong(stack[sp - 1])
                            ? (object)(ToI64(stack[sp - 1]) << shift)
                            : (object)(ToI32(stack[sp - 1]) << shift);
                        break;
                    }
                    case VMOpCode.Shr:
                    {
                        int shift = ToI32(stack[--sp]);
                        stack[sp - 1] = IsLong(stack[sp - 1])
                            ? (object)(ToI64(stack[sp - 1]) >> shift)
                            : (object)(ToI32(stack[sp - 1]) >> shift);
                        break;
                    }
                    case VMOpCode.Shr_Un:
                    {
                        int shift = ToI32(stack[--sp]);
                        stack[sp - 1] = IsLong(stack[sp - 1])
                            ? (object)((long)((ulong)ToI64(stack[sp - 1]) >> shift))
                            : (object)((int)((uint)ToI32(stack[sp - 1]) >> shift));
                        break;
                    }

                    case VMOpCode.Ceq:    { var b = stack[--sp]; var a = stack[--sp]; stack[sp++] = Cmp(a,b) == 0 ? 1 : 0; break; }
                    case VMOpCode.Cgt:    { var b = stack[--sp]; var a = stack[--sp]; stack[sp++] = Cmp(a,b) >  0 ? 1 : 0; break; }
                    case VMOpCode.Clt:    { var b = stack[--sp]; var a = stack[--sp]; stack[sp++] = Cmp(a,b) <  0 ? 1 : 0; break; }
                    case VMOpCode.Cgt_Un: { var b = stack[--sp]; var a = stack[--sp]; stack[sp++] = CmpUn(a,b) > 0 ? 1 : 0; break; }
                    case VMOpCode.Clt_Un: { var b = stack[--sp]; var a = stack[--sp]; stack[sp++] = CmpUn(a,b) < 0 ? 1 : 0; break; }

                    case VMOpCode.Conv_I1: stack[sp-1] = (int)(sbyte) ToI32(stack[sp-1]); break;
                    case VMOpCode.Conv_I2: stack[sp-1] = (int)(short) ToI32(stack[sp-1]); break;
                    case VMOpCode.Conv_I4: stack[sp-1] = ToI32(stack[sp-1]);               break;
                    case VMOpCode.Conv_I8: stack[sp-1] = ToI64(stack[sp-1]);               break;
                    case VMOpCode.Conv_U1: stack[sp-1] = (int)(byte)  ToI32(stack[sp-1]);  break;
                    case VMOpCode.Conv_U2: stack[sp-1] = (int)(ushort)ToI32(stack[sp-1]);  break;
                    case VMOpCode.Conv_U4: stack[sp-1] = (long)(uint) ToI32(stack[sp-1]);  break;
                    case VMOpCode.Conv_U8: stack[sp-1] = (long)(ulong)ToI64(stack[sp-1]);  break;
                    case VMOpCode.Conv_R4: stack[sp-1] = Convert.ToSingle(stack[sp-1]);    break;
                    case VMOpCode.Conv_R8: stack[sp-1] = Convert.ToDouble(stack[sp-1]);    break;

                    case VMOpCode.Br:
                        ip = ReadI32(code, ref ip);
                        break;

                    case VMOpCode.Brtrue:  { int t = ReadI32(code, ref ip); if ( IsTrue(stack[--sp]))   ip = t; break; }
                    case VMOpCode.Brfalse: { int t = ReadI32(code, ref ip); if (!IsTrue(stack[--sp]))   ip = t; break; }
                    case VMOpCode.Beq:     { int t = ReadI32(code, ref ip); var b = stack[--sp]; var a = stack[--sp]; if (Cmp(a,b)==0) ip=t; break; }
                    case VMOpCode.Bge:     { int t = ReadI32(code, ref ip); var b = stack[--sp]; var a = stack[--sp]; if (Cmp(a,b)>=0) ip=t; break; }
                    case VMOpCode.Bgt:     { int t = ReadI32(code, ref ip); var b = stack[--sp]; var a = stack[--sp]; if (Cmp(a,b)> 0) ip=t; break; }
                    case VMOpCode.Ble:     { int t = ReadI32(code, ref ip); var b = stack[--sp]; var a = stack[--sp]; if (Cmp(a,b)<=0) ip=t; break; }
                    case VMOpCode.Blt:     { int t = ReadI32(code, ref ip); var b = stack[--sp]; var a = stack[--sp]; if (Cmp(a,b)< 0) ip=t; break; }
                    case VMOpCode.Bne_Un:  { int t = ReadI32(code, ref ip); var b = stack[--sp]; var a = stack[--sp]; if (CmpUn(a,b)!=0) ip=t; break; }
                    case VMOpCode.Bge_Un:  { int t = ReadI32(code, ref ip); var b = stack[--sp]; var a = stack[--sp]; if (CmpUn(a,b)>=0) ip=t; break; }
                    case VMOpCode.Bgt_Un:  { int t = ReadI32(code, ref ip); var b = stack[--sp]; var a = stack[--sp]; if (CmpUn(a,b)> 0) ip=t; break; }
                    case VMOpCode.Ble_Un:  { int t = ReadI32(code, ref ip); var b = stack[--sp]; var a = stack[--sp]; if (CmpUn(a,b)<=0) ip=t; break; }
                    case VMOpCode.Blt_Un:  { int t = ReadI32(code, ref ip); var b = stack[--sp]; var a = stack[--sp]; if (CmpUn(a,b)< 0) ip=t; break; }

                    case VMOpCode.Ret_Val:
                        return stack[--sp];

                    case VMOpCode.Ret_Void:
                        return null;

                    case VMOpCode.Throw:
                    {
                        var ex       = (Exception)stack[--sp];
                        int throwIp  = ip - 1;
                        sp = 0;
                        int hIdx = FindCatchOrFinally(throwIp, ex, handlers, types);
                        if (hIdx < 0) throw ex; // nothing in the VM handles it — let the CLR deal with it

                        currentException  = ex;
                        currentHandlerIdx = hIdx;
                        var h = handlers[hIdx];
                        if (h.Type == 0) // catch: push the exception so handler code can access it
                        {
                            stack[sp++]      = ex;
                            currentException = null;
                        }
                        ip = h.HandlerStart;
                        break;
                    }

                    case VMOpCode.Leave:
                    {
                        int target  = ReadI32(code, ref ip);
                        int fromIp  = ip - 5; // position of the Leave opcode itself
                        sp = 0;               // Leave always clears the evaluation stack
                        currentException = null; // exiting a catch block clears the current exception

                        // Find every finally/fault handler we pass through on the way out.
                        // They need to run innermost-first before we reach the target offset.
                        pendingFinallys  = CollectFinallyHandlersForLeave(fromIp, target, handlers);
                        pendingFinallyPos = 0;
                        leaveTarget      = target;

                        if (pendingFinallys.Length > 0)
                        {
                            currentHandlerIdx = pendingFinallys[pendingFinallyPos++];
                            ip = handlers[currentHandlerIdx].HandlerStart;
                        }
                        else
                        {
                            ip = target;
                        }
                        break;
                    }

                    case VMOpCode.Endfinally:
                    {
                        if (currentException != null)
                        {
                            // We got here because an exception was propagating through this
                            // finally/fault block. Resume searching for a handler starting
                            // just past the try region we just finished.
                            int searchFrom = handlers[currentHandlerIdx].TryEnd;
                            int hIdx = FindCatchOrFinally(searchFrom - 1, currentException, handlers, types,
                                                          skipTryEnd: handlers[currentHandlerIdx].TryStart);
                            if (hIdx < 0)
                            {
                                var ex = currentException;
                                currentException = null;
                                throw ex;
                            }
                            currentHandlerIdx = hIdx;
                            var h2 = handlers[hIdx];
                            if (h2.Type == 0)
                            {
                                stack[sp++]      = currentException;
                                currentException = null;
                            }
                            ip = h2.HandlerStart;
                        }
                        else if (pendingFinallys != null && pendingFinallyPos < pendingFinallys.Length)
                        {
                            // Still more finallys to run for this Leave.
                            currentHandlerIdx = pendingFinallys[pendingFinallyPos++];
                            ip = handlers[currentHandlerIdx].HandlerStart;
                        }
                        else
                        {
                            // All finally blocks done — jump to where Leave wanted to go.
                            int target    = leaveTarget;
                            leaveTarget   = -1;
                            pendingFinallys   = null;
                            pendingFinallyPos = 0;
                            ip = target;
                        }
                        break;
                    }

                    case VMOpCode.Rethrow:
                    {
                        if (currentException == null)
                            throw new InvalidOperationException("Rethrow outside exception handler.");

                        // Treat rethrow like throw but skip handlers at the same nesting level —
                        // we want the *enclosing* handler, not this one again.
                        int rethrowIp = ip - 1;
                        int hIdx = FindCatchOrFinally(rethrowIp, currentException, handlers, types,
                                                      skipTryEnd: handlers[currentHandlerIdx].TryStart);
                        if (hIdx < 0)
                        {
                            var ex = currentException;
                            currentException = null;
                            throw ex;
                        }
                        currentHandlerIdx = hIdx;
                        var h3 = handlers[hIdx];
                        if (h3.Type == 0)
                        {
                            stack[sp++]      = currentException;
                            currentException = null;
                        }
                        ip = h3.HandlerStart;
                        break;
                    }

                    case VMOpCode.Call:
                    case VMOpCode.Callvirt:
                    {
                        int idx    = ReadI32(code, ref ip);
                        var method = methods[idx];
                        var parms  = method.GetParameters();
                        var callArgs = new object[parms.Length];
                        for (int i = parms.Length - 1; i >= 0; i--)
                            callArgs[i] = stack[--sp];

                        object instance = null;
                        if (!method.IsStatic) instance = stack[--sp];

                        var mi  = (MethodInfo)method;
                        object ret = mi.Invoke(instance, callArgs);
                        if (mi.ReturnType != typeof(void))
                            stack[sp++] = ret;
                        break;
                    }

                    case VMOpCode.Newobj:
                    {
                        int idx    = ReadI32(code, ref ip);
                        var ctor   = (ConstructorInfo)methods[idx];
                        var parms  = ctor.GetParameters();
                        var ctorArgs = new object[parms.Length];
                        for (int i = parms.Length - 1; i >= 0; i--)
                            ctorArgs[i] = stack[--sp];
                        stack[sp++] = ctor.Invoke(ctorArgs);
                        break;
                    }

                    case VMOpCode.Ldfld:  { int idx = ReadI32(code, ref ip); var obj = stack[--sp]; stack[sp++] = fields[idx].GetValue(obj); break; }
                    case VMOpCode.Stfld:  { int idx = ReadI32(code, ref ip); var val = stack[--sp]; var obj = stack[--sp]; fields[idx].SetValue(obj, val); break; }
                    case VMOpCode.Ldsfld: { int idx = ReadI32(code, ref ip); stack[sp++] = fields[idx].GetValue(null); break; }
                    case VMOpCode.Stsfld: { int idx = ReadI32(code, ref ip); fields[idx].SetValue(null, stack[--sp]); break; }

                    case VMOpCode.Box:
                        ReadI32(code, ref ip); // type index consumed; value is already boxed inside the VM
                        break;

                    case VMOpCode.Unbox_Any:
                    {
                        int idx = ReadI32(code, ref ip);
                        var val = stack[sp - 1];
                        stack[sp - 1] = types[idx].IsValueType
                            ? Convert.ChangeType(val, types[idx]) : val;
                        break;
                    }

                    case VMOpCode.Castclass:
                    {
                        int idx = ReadI32(code, ref ip);
                        var val = stack[sp - 1];
                        if (val != null && !types[idx].IsInstanceOfType(val))
                            throw new InvalidCastException($"Cannot cast {val.GetType()} to {types[idx]}");
                        break;
                    }

                    case VMOpCode.Isinst:
                    {
                        int idx = ReadI32(code, ref ip);
                        var val = stack[sp - 1];
                        stack[sp - 1] = types[idx].IsInstanceOfType(val) ? val : null;
                        break;
                    }

                    case VMOpCode.Initobj:
                        ReadI32(code, ref ip);
                        sp--;
                        break;

                    case VMOpCode.Newarr:
                    {
                        int idx = ReadI32(code, ref ip);
                        int len = ToI32(stack[--sp]);
                        stack[sp++] = Array.CreateInstance(types[idx], len);
                        break;
                    }

                    case VMOpCode.Ldlen:
                    {
                        var arr = (Array)stack[--sp];
                        stack[sp++] = arr.Length;
                        break;
                    }

                    case VMOpCode.Ldelem:
                    {
                        int arrIdx = ToI32(stack[--sp]);
                        var arr    = (Array)stack[--sp];
                        stack[sp++] = arr.GetValue(arrIdx);
                        break;
                    }

                    case VMOpCode.Stelem:
                    {
                        var val    = stack[--sp];
                        int arrIdx = ToI32(stack[--sp]);
                        var arr    = (Array)stack[--sp];
                        arr.SetValue(val, arrIdx);
                        break;
                    }

                    default:
                        throw new InvalidOperationException(
                            $"Unknown VM opcode 0x{(byte)op:X2} at offset {ip - 1}");
                }
            }
        }

        // Reads the binary handler table produced by MethodVirtualizer.SerializeHandlers.
        // Returns an empty array when there are no handlers (the common case).
        private static HandlerEntry[] ParseHandlerTable(byte[] ht)
        {
            if (ht == null || ht.Length < 4) return new HandlerEntry[0];
            int ip    = 0;
            int count = ReadI32Buf(ht, ref ip);
            var result = new HandlerEntry[count];
            for (int i = 0; i < count; i++)
            {
                result[i] = new HandlerEntry
                {
                    Type         = ReadI32Buf(ht, ref ip),
                    TryStart     = ReadI32Buf(ht, ref ip),
                    TryEnd       = ReadI32Buf(ht, ref ip),
                    HandlerStart = ReadI32Buf(ht, ref ip),
                    HandlerEnd   = ReadI32Buf(ht, ref ip),
                    CatchTypeIdx = ReadI32Buf(ht, ref ip),
                };
            }
            return result;
        }

        // Returns the innermost handler that covers ip and can handle ex.
        // "Innermost" means the handler with the smallest try region, matching
        // how the CLR resolves overlapping try blocks.
        //
        // skipTryEnd: when we're continuing dispatch after Endfinally, we must not
        // re-enter a try region we already left. Any handler whose TryStart is less
        // than skipTryEnd is in the region we came from and gets skipped.
        private static int FindCatchOrFinally(
            int ip, Exception ex, HandlerEntry[] handlers, Type[] types,
            int skipTryEnd = -1)
        {
            int bestIdx  = -1;
            int bestSize = int.MaxValue;
            for (int i = 0; i < handlers.Length; i++)
            {
                ref HandlerEntry h = ref handlers[i];
                if (skipTryEnd >= 0 && h.TryStart < skipTryEnd)
                    continue;

                if (ip < h.TryStart || ip >= h.TryEnd) continue;

                int size = h.TryEnd - h.TryStart;
                if (h.Type == 0) // catch: check type compatibility
                {
                    if (!types[h.CatchTypeIdx].IsInstanceOfType(ex)) continue;
                }
                // finally and fault always match

                if (size < bestSize)
                {
                    bestSize = size;
                    bestIdx  = i;
                }
            }
            return bestIdx;
        }

        // Collects the indices of all finally/fault handlers that sit between fromIp
        // and targetIp on the nesting stack — these are the blocks a Leave instruction
        // must run through before it can reach its destination.
        // The list comes back sorted innermost-first so we run them in the right order.
        private static int[] CollectFinallyHandlersForLeave(
            int fromIp, int targetIp, HandlerEntry[] handlers)
        {
            if (handlers.Length == 0) return new int[0];
            var list = new System.Collections.Generic.List<int>();
            for (int i = 0; i < handlers.Length; i++)
            {
                ref HandlerEntry h = ref handlers[i];
                if (h.Type == 0) continue; // Leave doesn't trigger catch handlers
                if (fromIp  >= h.TryStart && fromIp  < h.TryEnd &&
                    !(targetIp >= h.TryStart && targetIp < h.TryEnd))
                {
                    list.Add(i);
                }
            }
            list.Sort((a, b) =>
            {
                int sa = handlers[a].TryEnd - handlers[a].TryStart;
                int sb = handlers[b].TryEnd - handlers[b].TryStart;
                return sa.CompareTo(sb);
            });
            return list.ToArray();
        }

        // Little-endian binary readers shared by both the code stream and the handler table.

        static ushort ReadU16(byte[] c, ref int ip)
        {
            ushort v = (ushort)(c[ip] | (c[ip + 1] << 8));
            ip += 2; return v;
        }

        static int ReadI32(byte[] c, ref int ip)
        {
            int v = c[ip] | (c[ip+1] << 8) | (c[ip+2] << 16) | (c[ip+3] << 24);
            ip += 4; return v;
        }

        static int ReadI32Buf(byte[] c, ref int ip) => ReadI32(c, ref ip);

        static long ReadI64(byte[] c, ref int ip)
        {
            uint lo = (uint)ReadI32(c, ref ip);
            int  hi =       ReadI32(c, ref ip);
            return (long)lo | ((long)hi << 32);
        }

        static float  ReadR32(byte[] c, ref int ip) { float  v = BitConverter.ToSingle(c, ip); ip += 4; return v; }
        static double ReadR64(byte[] c, ref int ip) { double v = BitConverter.ToDouble(c, ip); ip += 8; return v; }

        static bool IsLong(object v)  => v is long || v is ulong;
        static int  ToI32(object v)   => Convert.ToInt32(v);
        static long ToI64(object v)   => Convert.ToInt64(v);

        static bool IsTrue(object v)
        {
            if (v == null) return false;
            if (v is bool b) return b;
            if (v is int  i) return i != 0;
            if (v is long l) return l != 0L;
            return true;
        }

        // Arithmetic helpers pick the widest type present on the stack, matching
        // CIL's numeric promotion: double > float > long > int.

        static object ArithAdd(object a, object b)
        {
            if (a is double || b is double) return Convert.ToDouble(a) + Convert.ToDouble(b);
            if (a is float  || b is float)  return Convert.ToSingle(a) + Convert.ToSingle(b);
            if (a is long   || b is long)   return ToI64(a) + ToI64(b);
            return ToI32(a) + ToI32(b);
        }
        static object ArithSub(object a, object b)
        {
            if (a is double || b is double) return Convert.ToDouble(a) - Convert.ToDouble(b);
            if (a is float  || b is float)  return Convert.ToSingle(a) - Convert.ToSingle(b);
            if (a is long   || b is long)   return ToI64(a) - ToI64(b);
            return ToI32(a) - ToI32(b);
        }
        static object ArithMul(object a, object b)
        {
            if (a is double || b is double) return Convert.ToDouble(a) * Convert.ToDouble(b);
            if (a is float  || b is float)  return Convert.ToSingle(a) * Convert.ToSingle(b);
            if (a is long   || b is long)   return ToI64(a) * ToI64(b);
            return ToI32(a) * ToI32(b);
        }
        static object ArithDiv(object a, object b)
        {
            if (a is double || b is double) return Convert.ToDouble(a) / Convert.ToDouble(b);
            if (a is float  || b is float)  return Convert.ToSingle(a) / Convert.ToSingle(b);
            if (a is long   || b is long)   return ToI64(a) / ToI64(b);
            return ToI32(a) / ToI32(b);
        }
        static object ArithRem(object a, object b)
        {
            if (a is double || b is double) return Convert.ToDouble(a) % Convert.ToDouble(b);
            if (a is float  || b is float)  return Convert.ToSingle(a) % Convert.ToSingle(b);
            if (a is long   || b is long)   return ToI64(a) % ToI64(b);
            return ToI32(a) % ToI32(b);
        }
        static object ArithNeg(object a)
        {
            if (a is double d) return -d;
            if (a is float  f) return -f;
            if (a is long   l) return -l;
            return -ToI32(a);
        }

        static object BitwiseAnd(object a, object b)
        {
            if (a is long || b is long) return ToI64(a) & ToI64(b);
            return ToI32(a) & ToI32(b);
        }
        static object BitwiseOr(object a, object b)
        {
            if (a is long || b is long) return ToI64(a) | ToI64(b);
            return ToI32(a) | ToI32(b);
        }
        static object BitwiseXor(object a, object b)
        {
            if (a is long || b is long) return ToI64(a) ^ ToI64(b);
            return ToI32(a) ^ ToI32(b);
        }
        static object BitwiseNot(object a)
        {
            if (a is long l) return ~l;
            return ~ToI32(a);
        }

        static int Cmp(object a, object b)
        {
            if (a is double da) return da.CompareTo(Convert.ToDouble(b));
            if (a is float  fa) return fa.CompareTo(Convert.ToSingle(b));
            if (a is long || b is long) return ToI64(a).CompareTo(ToI64(b));
            if (a is int  || b is int)  return ToI32(a).CompareTo(ToI32(b));
            if (a == null && b == null) return 0;
            if (a == null) return -1;
            if (b == null) return 1;
            if (a is IComparable ic) return ic.CompareTo(b);
            return Equals(a, b) ? 0 : -1;
        }

        // CmpUn: unordered comparison — NaN comparisons return 1 (unordered),
        // integers are treated as unsigned.
        static int CmpUn(object a, object b)
        {
            if (a is double da)
            {
                double db = Convert.ToDouble(b);
                if (double.IsNaN(da) || double.IsNaN(db)) return 1;
                return da.CompareTo(db);
            }
            if (a is float fa)
            {
                float fb = Convert.ToSingle(b);
                if (float.IsNaN(fa) || float.IsNaN(fb)) return 1;
                return fa.CompareTo(fb);
            }
            if (a is long || b is long)
                return ((ulong)ToI64(a)).CompareTo((ulong)ToI64(b));
            return ((uint)ToI32(a)).CompareTo((uint)ToI32(b));
        }
    }
}
