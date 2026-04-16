using System;
using System.Collections.Generic;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using DnlibTypeAttributes       = dnlib.DotNet.TypeAttributes;
using DnlibFieldAttributes      = dnlib.DotNet.FieldAttributes;
using DnlibMethodAttributes     = dnlib.DotNet.MethodAttributes;
using DnlibMethodImplAttributes = dnlib.DotNet.MethodImplAttributes;

namespace ByteVM.Core
{
    // Builds __VMData__ inside the target module and rewrites each virtualized
    // method body to a thin stub that forwards into the VM interpreter.
    // Also handles embedding the runtime DLL as a resource when self-contained
    // mode is on (so the output needs no external ByteVM.Runtime.dll next to it).
    internal class RuntimeInjector
    {
        private readonly ModuleDefMD  _module;
        private readonly ICorLibTypes _cor;
        private readonly AssemblyRef  _corlibRef;

        // TypeRefs the static ctor and stubs need
        private TypeRef _typeType;
        private TypeRef _methodBaseType;
        private TypeRef _fieldInfoType;
        private TypeRef _runtimeTypeHandleType;
        private TypeRef _runtimeMethodHandleType;
        private TypeRef _runtimeFieldHandleType;
        private TypeRef _convertType;
        private TypeRef _vmInterpreterType;

        // MemberRefs for the three ldtoken helpers + base64 + Execute itself
        private MemberRef _getTypeFromHandle;
        private MemberRef _getMethodFromHandle;
        private MemberRef _getFieldFromHandle;
        private MemberRef _fromBase64String;
        private MemberRef _vmExecute;

        // Extra refs only needed when embedding the runtime (self-contained mode)
        private TypeRef   _appDomainType;
        private TypeRef   _resolveEventArgsType;
        private TypeRef   _assemblyType;
        private TypeRef   _resolveEventHandlerType;
        private TypeRef   _streamType;
        private TypeRef   _iDisposableType;

        private MemberRef _appDomainGetCurrentDomain;
        private MemberRef _appDomainAddAssemblyResolve;
        private MemberRef _resolveEventHandlerCtor;
        private MemberRef _resolveEventArgsGetName;
        private MemberRef _stringStartsWith;
        private MemberRef _typeGetAssembly;
        private MemberRef _assemblyGetManifestResourceStream;
        private MemberRef _streamGetLength;
        private MemberRef _streamRead;
        private MemberRef _iDisposableDispose;
        private MemberRef _assemblyLoad;

        // Fields injected into __VMData__
        private TypeDef  _vmDataType;
        private FieldDef _fldDecodeTable;    // byte[]   — opcode shuffle table, stored XOR'd
        private FieldDef _fldBytecodes;      // byte[][] — one encrypted bytecode blob per method
        private FieldDef _fldKeyPartsA;      // byte[][] — first half of each method's XOR key
        private FieldDef _fldKeyPartsB;      // byte[][] — second half, stored obfuscated (XOR'd with hash of A)
        private FieldDef _fldHandlerTables;  // byte[][] — serialized exception handler entries per method
        private FieldDef _fldLocalCounts;    // int[]
        private FieldDef _fldMethods;        // MethodBase[]
        private FieldDef _fldFields;         // FieldInfo[]
        private FieldDef _fldTypes;          // Type[]

        public RuntimeInjector(ModuleDefMD module)
        {
            _module    = module;
            _cor       = module.CorLibTypes;
            _corlibRef = _cor.AssemblyRef;
        }

        public void Inject(
            List<IMethod>           methodTable,
            List<IField>            fieldTable,
            List<ITypeDefOrRef>     typeTable,
            List<VirtualizedMethod> vms,
            byte[]  decodeTable,
            byte    decodeTableKey,
            string  runtimeAssemblyName,
            Version runtimeVersion,
            byte[]  runtimeDllBytes = null)
        {
            BuildTypeRefs(runtimeAssemblyName, runtimeVersion);
            CreateVMDataType();

            // __Resolve__ has to exist before GenerateStaticCtor so ldftn can reference it.
            // Same reason InjectModuleInitializer comes here rather than inside the cctor.
            MethodDef resolveMethod = null;
            if (runtimeDllBytes != null)
            {
                BuildPhase4TypeRefs();
                resolveMethod = CreateResolveMethod();
                EmbedRuntimeResource(runtimeDllBytes);
                InjectModuleInitializer(resolveMethod);
            }

            GenerateStaticCtor(methodTable, fieldTable, typeTable, vms,
                               decodeTable, decodeTableKey, resolveMethod);

            foreach (var vm in vms)
                ReplaceMethodBody(vm);
        }

        private void BuildTypeRefs(string runtimeAssemblyName, Version runtimeVersion)
        {
            _typeType                = new TypeRefUser(_module, "System",            "Type",                _corlibRef);
            _methodBaseType          = new TypeRefUser(_module, "System.Reflection", "MethodBase",          _corlibRef);
            _fieldInfoType           = new TypeRefUser(_module, "System.Reflection", "FieldInfo",           _corlibRef);
            _runtimeTypeHandleType   = new TypeRefUser(_module, "System",            "RuntimeTypeHandle",   _corlibRef);
            _runtimeMethodHandleType = new TypeRefUser(_module, "System",            "RuntimeMethodHandle", _corlibRef);
            _runtimeFieldHandleType  = new TypeRefUser(_module, "System",            "RuntimeFieldHandle",  _corlibRef);
            _convertType             = new TypeRefUser(_module, "System",            "Convert",             _corlibRef);

            _getTypeFromHandle = new MemberRefUser(_module, "GetTypeFromHandle",
                MethodSig.CreateStatic(new ClassSig(_typeType),
                    new ValueTypeSig(_runtimeTypeHandleType)), _typeType);

            _getMethodFromHandle = new MemberRefUser(_module, "GetMethodFromHandle",
                MethodSig.CreateStatic(new ClassSig(_methodBaseType),
                    new ValueTypeSig(_runtimeMethodHandleType)), _methodBaseType);

            _getFieldFromHandle = new MemberRefUser(_module, "GetFieldFromHandle",
                MethodSig.CreateStatic(new ClassSig(_fieldInfoType),
                    new ValueTypeSig(_runtimeFieldHandleType)), _fieldInfoType);

            _fromBase64String = new MemberRefUser(_module, "FromBase64String",
                MethodSig.CreateStatic(new SZArraySig(_cor.Byte), _cor.String), _convertType);

            var runtimeRef = new AssemblyRefUser(
                new AssemblyNameInfo(runtimeAssemblyName) { Version = runtimeVersion });
            _vmInterpreterType = new TypeRefUser(_module, "ByteVM.Runtime", "VMInterpreter", runtimeRef);

            // MemberRef for Execute — signature must match VMInterpreter exactly.
            // Params: encryptedCode, localsCount, args, keyA, keyB, decodeTable,
            //         handlerTable, methods, fields, types
            _vmExecute = new MemberRefUser(_module, "Execute",
                MethodSig.CreateStatic(
                    _cor.Object,
                    new SZArraySig(_cor.Byte),                     // encryptedCode
                    _cor.Int32,                                    // localsCount
                    new SZArraySig(_cor.Object),                   // args
                    new SZArraySig(_cor.Byte),                     // keyA
                    new SZArraySig(_cor.Byte),                     // keyB
                    new SZArraySig(_cor.Byte),                     // decodeTable
                    new SZArraySig(_cor.Byte),                     // handlerTable
                    new SZArraySig(new ClassSig(_methodBaseType)), // methods
                    new SZArraySig(new ClassSig(_fieldInfoType)),   // fields
                    new SZArraySig(new ClassSig(_typeType))),       // types
                _vmInterpreterType);
        }

        // Only needed when embedding the runtime — skip building these if not self-contained.
        private void BuildPhase4TypeRefs()
        {
            _appDomainType            = new TypeRefUser(_module, "System",           "AppDomain",            _corlibRef);
            _resolveEventArgsType     = new TypeRefUser(_module, "System",           "ResolveEventArgs",     _corlibRef);
            _assemblyType             = new TypeRefUser(_module, "System.Reflection","Assembly",             _corlibRef);
            _resolveEventHandlerType  = new TypeRefUser(_module, "System",           "ResolveEventHandler",  _corlibRef);
            _streamType               = new TypeRefUser(_module, "System.IO",        "Stream",               _corlibRef);
            _iDisposableType          = new TypeRefUser(_module, "System",           "IDisposable",          _corlibRef);

            _appDomainGetCurrentDomain = new MemberRefUser(_module, "get_CurrentDomain",
                MethodSig.CreateStatic(new ClassSig(_appDomainType)), _appDomainType);

            _appDomainAddAssemblyResolve = new MemberRefUser(_module, "add_AssemblyResolve",
                MethodSig.CreateInstance(_cor.Void, new ClassSig(_resolveEventHandlerType)),
                _appDomainType);

            _resolveEventHandlerCtor = new MemberRefUser(_module, ".ctor",
                MethodSig.CreateInstance(_cor.Void, _cor.Object, _cor.IntPtr),
                _resolveEventHandlerType);

            _resolveEventArgsGetName = new MemberRefUser(_module, "get_Name",
                MethodSig.CreateInstance(_cor.String), _resolveEventArgsType);

            _stringStartsWith = new MemberRefUser(_module, "StartsWith",
                MethodSig.CreateInstance(_cor.Boolean, _cor.String),
                (ITypeDefOrRef)_cor.String.TypeDefOrRef);

            _typeGetAssembly = new MemberRefUser(_module, "get_Assembly",
                MethodSig.CreateInstance(new ClassSig(_assemblyType)), _typeType);

            _assemblyGetManifestResourceStream = new MemberRefUser(_module, "GetManifestResourceStream",
                MethodSig.CreateInstance(new ClassSig(_streamType), _cor.String),
                _assemblyType);

            _streamGetLength = new MemberRefUser(_module, "get_Length",
                MethodSig.CreateInstance(_cor.Int64), _streamType);

            _streamRead = new MemberRefUser(_module, "Read",
                MethodSig.CreateInstance(_cor.Int32,
                    new SZArraySig(_cor.Byte), _cor.Int32, _cor.Int32),
                _streamType);

            _iDisposableDispose = new MemberRefUser(_module, "Dispose",
                MethodSig.CreateInstance(_cor.Void), _iDisposableType);

            _assemblyLoad = new MemberRefUser(_module, "Load",
                MethodSig.CreateStatic(new ClassSig(_assemblyType),
                    new SZArraySig(_cor.Byte)),
                _assemblyType);
        }

        private void CreateVMDataType()
        {
            // sealed abstract = static class in IL terms — no instances, no subclasses
            _vmDataType = new TypeDefUser(string.Empty, "__VMData__",
                _module.CorLibTypes.Object.TypeDefOrRef);
            _vmDataType.Attributes =
                DnlibTypeAttributes.NotPublic  |
                DnlibTypeAttributes.Sealed     |
                DnlibTypeAttributes.Abstract   |
                DnlibTypeAttributes.BeforeFieldInit;

            var sa = DnlibFieldAttributes.Static | DnlibFieldAttributes.Assembly;

            _fldDecodeTable   = new FieldDefUser("DecodeTable",
                new FieldSig(new SZArraySig(_cor.Byte)), sa);

            _fldBytecodes     = new FieldDefUser("Bytecodes",
                new FieldSig(new SZArraySig(new SZArraySig(_cor.Byte))), sa);

            _fldKeyPartsA     = new FieldDefUser("KeyPartsA",
                new FieldSig(new SZArraySig(new SZArraySig(_cor.Byte))), sa);

            _fldKeyPartsB     = new FieldDefUser("KeyPartsB",
                new FieldSig(new SZArraySig(new SZArraySig(_cor.Byte))), sa);

            _fldHandlerTables = new FieldDefUser("HandlerTables",
                new FieldSig(new SZArraySig(new SZArraySig(_cor.Byte))), sa);

            _fldLocalCounts   = new FieldDefUser("LocalCounts",
                new FieldSig(new SZArraySig(_cor.Int32)), sa);

            _fldMethods       = new FieldDefUser("Methods",
                new FieldSig(new SZArraySig(new ClassSig(_methodBaseType))), sa);

            _fldFields        = new FieldDefUser("Fields",
                new FieldSig(new SZArraySig(new ClassSig(_fieldInfoType))), sa);

            _fldTypes         = new FieldDefUser("Types",
                new FieldSig(new SZArraySig(new ClassSig(_typeType))), sa);

            foreach (var f in new FieldDef[] {
                _fldDecodeTable, _fldBytecodes,
                _fldKeyPartsA, _fldKeyPartsB,
                _fldHandlerTables, _fldLocalCounts,
                _fldMethods, _fldFields, _fldTypes })
                _vmDataType.Fields.Add(f);

            _module.Types.Add(_vmDataType);
        }

        private void EmbedRuntimeResource(byte[] runtimeDllBytes)
        {
            _module.Resources.Add(new EmbeddedResource("__vm_rt__", runtimeDllBytes));
        }

        // Registers the AssemblyResolve hook inside <Module>::.cctor rather than
        // __VMData__::.cctor. The reason: when the CLR JIT-compiles a stub method it
        // immediately tries to resolve the VMInterpreter.Execute token, which loads
        // ByteVM.Runtime — this happens before any IL in the stub runs, so before
        // __VMData__ is ever initialized. The module initializer on the other hand
        // fires the moment the assembly is loaded, before any JIT work, so the hook
        // is already live by the time it's needed.
        private void InjectModuleInitializer(MethodDef resolveMethod)
        {
            var globalType = _module.GlobalType;

            var hookInstrs = new Instruction[]
            {
                Instruction.Create(OpCodes.Call,     _appDomainGetCurrentDomain),
                Instruction.Create(OpCodes.Ldnull),
                Instruction.Create(OpCodes.Ldftn,    resolveMethod),
                Instruction.Create(OpCodes.Newobj,   _resolveEventHandlerCtor),
                Instruction.Create(OpCodes.Callvirt, _appDomainAddAssemblyResolve),
            };

            MethodDef existing = globalType.FindStaticConstructor();
            if (existing != null && existing.HasBody)
            {
                // Prepend — reverse order so index 0 ends up first after all inserts
                for (int i = hookInstrs.Length - 1; i >= 0; i--)
                    existing.Body.Instructions.Insert(0, hookInstrs[i]);
            }
            else
            {
                var body = new CilBody();
                foreach (var ins in hookInstrs)
                    body.Instructions.Add(ins);
                body.Instructions.Add(Instruction.Create(OpCodes.Ret));

                var cctor = new MethodDefUser(".cctor",
                    MethodSig.CreateStatic(_cor.Void),
                    DnlibMethodImplAttributes.IL | DnlibMethodImplAttributes.Managed,
                    DnlibMethodAttributes.Private | DnlibMethodAttributes.Static |
                    DnlibMethodAttributes.HideBySig | DnlibMethodAttributes.SpecialName |
                    DnlibMethodAttributes.RTSpecialName);
                cctor.Body = body;
                globalType.Methods.Add(cctor);
            }
        }

        // Generates __Resolve__ inside __VMData__.
        // At runtime this is called by the CLR whenever an assembly fails to load.
        // It checks whether the failing name starts with "ByteVM.Runtime", reads the
        // "__vm_rt__" embedded resource out of this assembly, and loads it from bytes.
        private MethodDef CreateResolveMethod()
        {
            var body = new CilBody();
            var ins  = body.Instructions;

            var locName  = new Local(_cor.String);
            var locAsm   = new Local(new ClassSig(_assemblyType));
            var locS     = new Local(new ClassSig(_streamType));
            var locBytes = new Local(new SZArraySig(_cor.Byte));
            body.Variables.Add(locName);
            body.Variables.Add(locAsm);
            body.Variables.Add(locS);
            body.Variables.Add(locBytes);

            // Jump target for all early exits
            var retNull = Instruction.Create(OpCodes.Ldnull);

            ins.Add(Instruction.Create(OpCodes.Ldarg_1));
            ins.Add(Instruction.Create(OpCodes.Callvirt, _resolveEventArgsGetName));
            ins.Add(Instruction.Create(OpCodes.Stloc, locName));

            ins.Add(Instruction.Create(OpCodes.Ldloc, locName));
            ins.Add(Instruction.Create(OpCodes.Brfalse, retNull));

            ins.Add(Instruction.Create(OpCodes.Ldloc, locName));
            ins.Add(Instruction.Create(OpCodes.Ldstr, "ByteVM.Runtime"));
            ins.Add(Instruction.Create(OpCodes.Callvirt, _stringStartsWith));
            ins.Add(Instruction.Create(OpCodes.Brfalse, retNull));

            // Get the assembly object that contains the embedded resource.
            // typeof(__VMData__) is safe here — __VMData__ lives in the protected assembly.
            ins.Add(Instruction.Create(OpCodes.Ldtoken, _vmDataType));
            ins.Add(Instruction.Create(OpCodes.Call, _getTypeFromHandle));
            ins.Add(Instruction.Create(OpCodes.Callvirt, _typeGetAssembly));
            ins.Add(Instruction.Create(OpCodes.Stloc, locAsm));

            ins.Add(Instruction.Create(OpCodes.Ldloc, locAsm));
            ins.Add(Instruction.Create(OpCodes.Ldstr, "__vm_rt__"));
            ins.Add(Instruction.Create(OpCodes.Callvirt, _assemblyGetManifestResourceStream));
            ins.Add(Instruction.Create(OpCodes.Stloc, locS));

            ins.Add(Instruction.Create(OpCodes.Ldloc, locS));
            ins.Add(Instruction.Create(OpCodes.Brfalse, retNull));

            ins.Add(Instruction.Create(OpCodes.Ldloc, locS));
            ins.Add(Instruction.Create(OpCodes.Callvirt, _streamGetLength));
            ins.Add(Instruction.Create(OpCodes.Conv_I4));
            ins.Add(Instruction.Create(OpCodes.Newarr, (ITypeDefOrRef)_cor.Byte.TypeDefOrRef));
            ins.Add(Instruction.Create(OpCodes.Stloc, locBytes));

            ins.Add(Instruction.Create(OpCodes.Ldloc, locS));
            ins.Add(Instruction.Create(OpCodes.Ldloc, locBytes));
            ins.Add(Instruction.CreateLdcI4(0));
            ins.Add(Instruction.Create(OpCodes.Ldloc, locBytes));
            ins.Add(Instruction.Create(OpCodes.Ldlen));
            ins.Add(Instruction.Create(OpCodes.Conv_I4));
            ins.Add(Instruction.Create(OpCodes.Callvirt, _streamRead));
            ins.Add(Instruction.Create(OpCodes.Pop));

            ins.Add(Instruction.Create(OpCodes.Ldloc, locS));
            ins.Add(Instruction.Create(OpCodes.Callvirt, _iDisposableDispose));

            ins.Add(Instruction.Create(OpCodes.Ldloc, locBytes));
            ins.Add(Instruction.Create(OpCodes.Call, _assemblyLoad));
            ins.Add(Instruction.Create(OpCodes.Ret));

            ins.Add(retNull);
            ins.Add(Instruction.Create(OpCodes.Ret));

            body.OptimizeMacros();

            var resolveMethod = new MethodDefUser("__Resolve__",
                MethodSig.CreateStatic(
                    new ClassSig(_assemblyType),
                    _cor.Object,
                    new ClassSig(_resolveEventArgsType)),
                DnlibMethodImplAttributes.IL | DnlibMethodImplAttributes.Managed,
                DnlibMethodAttributes.Assembly | DnlibMethodAttributes.Static |
                DnlibMethodAttributes.HideBySig);
            resolveMethod.Body = body;
            _vmDataType.Methods.Add(resolveMethod);
            return resolveMethod;
        }

        private void GenerateStaticCtor(
            List<IMethod>           methodTable,
            List<IField>            fieldTable,
            List<ITypeDefOrRef>     typeTable,
            List<VirtualizedMethod> vms,
            byte[]     decodeTable,
            byte       decodeTableKey,
            MethodDef  resolveMethod)
        {
            var body = new CilBody();
            var ins  = body.Instructions;

            // Two locals needed for the decode-table XOR loop
            var locDt = new Local(new SZArraySig(_cor.Byte));
            var locI  = new Local(_cor.Int32);
            body.Variables.Add(locDt);
            body.Variables.Add(locI);

            // The decode table is stored scrambled (each byte XOR'd with decodeTableKey).
            // The loop below runs at runtime to get the real table back.
            byte[] encodedTable = (byte[])decodeTable.Clone();
            for (int i = 0; i < encodedTable.Length; i++)
                encodedTable[i] ^= decodeTableKey;

            ins.Add(Instruction.Create(OpCodes.Ldstr, Convert.ToBase64String(encodedTable)));
            ins.Add(Instruction.Create(OpCodes.Call, _fromBase64String));
            ins.Add(Instruction.Create(OpCodes.Stloc, locDt));

            ins.Add(Instruction.CreateLdcI4(0));
            ins.Add(Instruction.Create(OpCodes.Stloc, locI));

            var loopCheck = Instruction.Create(OpCodes.Ldloc, locI);
            var loopEnd   = Instruction.Create(OpCodes.Ldloc, locDt); // first instr after loop

            ins.Add(loopCheck);
            ins.Add(Instruction.CreateLdcI4(256));
            ins.Add(Instruction.Create(OpCodes.Bge, loopEnd));

            // dt[i] ^= decodeTableKey
            ins.Add(Instruction.Create(OpCodes.Ldloc, locDt));
            ins.Add(Instruction.Create(OpCodes.Ldloc, locI));
            ins.Add(Instruction.Create(OpCodes.Ldloc, locDt));
            ins.Add(Instruction.Create(OpCodes.Ldloc, locI));
            ins.Add(Instruction.Create(OpCodes.Ldelem_U1));
            ins.Add(Instruction.CreateLdcI4(decodeTableKey));
            ins.Add(Instruction.Create(OpCodes.Xor));
            ins.Add(Instruction.Create(OpCodes.Stelem_I1));

            ins.Add(Instruction.Create(OpCodes.Ldloc, locI));
            ins.Add(Instruction.CreateLdcI4(1));
            ins.Add(Instruction.Create(OpCodes.Add));
            ins.Add(Instruction.Create(OpCodes.Stloc, locI));
            ins.Add(Instruction.Create(OpCodes.Br, loopCheck));

            ins.Add(loopEnd);
            ins.Add(Instruction.Create(OpCodes.Stsfld, _fldDecodeTable));

            // Store encrypted bytecodes, key halves, and handler tables as base64 strings.
            // Convert.FromBase64String is called at class init time to decode them.
            EmitByteArrayArrayInit(ins, vms.Count, i => vms[i].Bytecode,     _fldBytecodes);
            EmitByteArrayArrayInit(ins, vms.Count, i => vms[i].KeyA,         _fldKeyPartsA);
            EmitByteArrayArrayInit(ins, vms.Count, i => vms[i].KeyB,         _fldKeyPartsB);
            EmitByteArrayArrayInit(ins, vms.Count, i => vms[i].HandlerTable, _fldHandlerTables);

            ins.Add(Instruction.CreateLdcI4(vms.Count));
            ins.Add(Instruction.Create(OpCodes.Newarr, (ITypeDefOrRef)_cor.Int32.TypeDefOrRef));
            for (int i = 0; i < vms.Count; i++)
            {
                ins.Add(Instruction.Create(OpCodes.Dup));
                ins.Add(Instruction.CreateLdcI4(i));
                ins.Add(Instruction.CreateLdcI4(vms[i].LocalsCount));
                ins.Add(Instruction.Create(OpCodes.Stelem_I4));
            }
            ins.Add(Instruction.Create(OpCodes.Stsfld, _fldLocalCounts));

            // ldtoken + GetXxxFromHandle is the only way to get reflection objects
            // without loading and searching through every type at runtime.
            EmitTableInit_Methods(ins, methodTable);
            ins.Add(Instruction.Create(OpCodes.Stsfld, _fldMethods));

            EmitTableInit_Fields(ins, fieldTable);
            ins.Add(Instruction.Create(OpCodes.Stsfld, _fldFields));

            EmitTableInit_Types(ins, typeTable);
            ins.Add(Instruction.Create(OpCodes.Stsfld, _fldTypes));

            ins.Add(Instruction.Create(OpCodes.Ret));

            body.OptimizeMacros();

            var cctor = new MethodDefUser(".cctor",
                MethodSig.CreateStatic(_cor.Void),
                DnlibMethodImplAttributes.IL | DnlibMethodImplAttributes.Managed,
                DnlibMethodAttributes.Private | DnlibMethodAttributes.Static |
                DnlibMethodAttributes.HideBySig | DnlibMethodAttributes.SpecialName |
                DnlibMethodAttributes.RTSpecialName);
            cctor.Body = body;
            _vmDataType.Methods.Add(cctor);
        }

        // Emits: field = new byte[count][] { FromBase64(s0), FromBase64(s1), ... }
        private void EmitByteArrayArrayInit(
            IList<Instruction> ins,
            int count,
            Func<int, byte[]> getBytes,
            FieldDef fld)
        {
            ins.Add(Instruction.CreateLdcI4(count));
            ins.Add(Instruction.Create(OpCodes.Newarr,
                new TypeSpecUser(new SZArraySig(_cor.Byte))));
            for (int i = 0; i < count; i++)
            {
                byte[] bytes = getBytes(i);
                ins.Add(Instruction.Create(OpCodes.Dup));
                ins.Add(Instruction.CreateLdcI4(i));
                ins.Add(Instruction.Create(OpCodes.Ldstr, Convert.ToBase64String(bytes)));
                ins.Add(Instruction.Create(OpCodes.Call, _fromBase64String));
                ins.Add(Instruction.Create(OpCodes.Stelem_Ref));
            }
            ins.Add(Instruction.Create(OpCodes.Stsfld, fld));
        }

        private void EmitTableInit_Methods(IList<Instruction> ins, List<IMethod> table)
        {
            ins.Add(Instruction.CreateLdcI4(table.Count));
            ins.Add(Instruction.Create(OpCodes.Newarr, _methodBaseType));
            for (int i = 0; i < table.Count; i++)
            {
                ins.Add(Instruction.Create(OpCodes.Dup));
                ins.Add(Instruction.CreateLdcI4(i));
                ins.Add(Instruction.Create(OpCodes.Ldtoken, table[i]));
                ins.Add(Instruction.Create(OpCodes.Call, _getMethodFromHandle));
                ins.Add(Instruction.Create(OpCodes.Stelem_Ref));
            }
        }

        private void EmitTableInit_Fields(IList<Instruction> ins, List<IField> table)
        {
            ins.Add(Instruction.CreateLdcI4(table.Count));
            ins.Add(Instruction.Create(OpCodes.Newarr, _fieldInfoType));
            for (int i = 0; i < table.Count; i++)
            {
                ins.Add(Instruction.Create(OpCodes.Dup));
                ins.Add(Instruction.CreateLdcI4(i));
                ins.Add(Instruction.Create(OpCodes.Ldtoken, table[i]));
                ins.Add(Instruction.Create(OpCodes.Call, _getFieldFromHandle));
                ins.Add(Instruction.Create(OpCodes.Stelem_Ref));
            }
        }

        private void EmitTableInit_Types(IList<Instruction> ins, List<ITypeDefOrRef> table)
        {
            ins.Add(Instruction.CreateLdcI4(table.Count));
            ins.Add(Instruction.Create(OpCodes.Newarr, _typeType));
            for (int i = 0; i < table.Count; i++)
            {
                ins.Add(Instruction.Create(OpCodes.Dup));
                ins.Add(Instruction.CreateLdcI4(i));
                ins.Add(Instruction.Create(OpCodes.Ldtoken, table[i]));
                ins.Add(Instruction.Create(OpCodes.Call, _getTypeFromHandle));
                ins.Add(Instruction.Create(OpCodes.Stelem_Ref));
            }
        }

        // Replaces the original method body with a stub that:
        //   1. packs all arguments into an object[]
        //   2. emits some junk arithmetic to pollute decompiler output
        //   3. calls VMInterpreter.Execute with the packed args + per-method data
        //   4. unpacks the return value (unbox/cast) if the method is non-void
        private void ReplaceMethodBody(VirtualizedMethod vm)
        {
            var method      = vm.Method;
            int methodIndex = vm.MethodIndex;
            bool isVoid     = vm.IsVoid;

            var body = new CilBody();
            var ins  = body.Instructions;

            var argsLocal = new Local(new SZArraySig(_cor.Object));
            body.Variables.Add(argsLocal);

            int argCount = method.Parameters.Count;

            ins.Add(Instruction.CreateLdcI4(argCount));
            ins.Add(Instruction.Create(OpCodes.Newarr,
                (ITypeDefOrRef)_cor.Object.TypeDefOrRef));
            for (int i = 0; i < argCount; i++)
            {
                var param = method.Parameters[i];
                ins.Add(Instruction.Create(OpCodes.Dup));
                ins.Add(Instruction.CreateLdcI4(i));
                ins.Add(Instruction.Create(OpCodes.Ldarg, param));
                if (param.Type.IsValueType)
                    ins.Add(Instruction.Create(OpCodes.Box, param.Type.ToTypeDefOrRef()));
                ins.Add(Instruction.Create(OpCodes.Stelem_Ref));
            }
            ins.Add(Instruction.Create(OpCodes.Stloc, argsLocal));

            // Dead computation — result is always 0 because of the final AND with 0.
            // Different seed per method so each stub looks distinct to a pattern scanner.
            int junkSeed = unchecked((methodIndex * (int)0x9E3779B9) ^ (int)0xDEADBEEF);
            ins.Add(Instruction.CreateLdcI4(junkSeed));
            ins.Add(Instruction.CreateLdcI4(methodIndex + 1));
            ins.Add(Instruction.Create(OpCodes.Mul));
            ins.Add(Instruction.CreateLdcI4(0));
            ins.Add(Instruction.Create(OpCodes.And));
            ins.Add(Instruction.Create(OpCodes.Pop));

            // Second junk — load a field then throw it away
            ins.Add(Instruction.Create(OpCodes.Ldsfld, _fldDecodeTable));
            ins.Add(Instruction.Create(OpCodes.Pop));

            // Push the 10 arguments Execute expects, then call it
            ins.Add(Instruction.Create(OpCodes.Ldsfld, _fldBytecodes));
            ins.Add(Instruction.CreateLdcI4(methodIndex));
            ins.Add(Instruction.Create(OpCodes.Ldelem_Ref));

            ins.Add(Instruction.Create(OpCodes.Ldsfld, _fldLocalCounts));
            ins.Add(Instruction.CreateLdcI4(methodIndex));
            ins.Add(Instruction.Create(OpCodes.Ldelem_I4));

            ins.Add(Instruction.Create(OpCodes.Ldloc, argsLocal));

            ins.Add(Instruction.Create(OpCodes.Ldsfld, _fldKeyPartsA));
            ins.Add(Instruction.CreateLdcI4(methodIndex));
            ins.Add(Instruction.Create(OpCodes.Ldelem_Ref));

            ins.Add(Instruction.Create(OpCodes.Ldsfld, _fldKeyPartsB));
            ins.Add(Instruction.CreateLdcI4(methodIndex));
            ins.Add(Instruction.Create(OpCodes.Ldelem_Ref));

            ins.Add(Instruction.Create(OpCodes.Ldsfld, _fldDecodeTable));

            ins.Add(Instruction.Create(OpCodes.Ldsfld, _fldHandlerTables));
            ins.Add(Instruction.CreateLdcI4(methodIndex));
            ins.Add(Instruction.Create(OpCodes.Ldelem_Ref));

            ins.Add(Instruction.Create(OpCodes.Ldsfld, _fldMethods));
            ins.Add(Instruction.Create(OpCodes.Ldsfld, _fldFields));
            ins.Add(Instruction.Create(OpCodes.Ldsfld, _fldTypes));

            ins.Add(Instruction.Create(OpCodes.Call, _vmExecute));

            if (isVoid)
            {
                ins.Add(Instruction.Create(OpCodes.Pop));
            }
            else
            {
                // Execute returns object, so we need to unbox/cast back to the real type
                var retType = method.ReturnType;
                if (retType.IsValueType)
                    ins.Add(Instruction.Create(OpCodes.Unbox_Any, retType.ToTypeDefOrRef()));
                else if (retType.ElementType != ElementType.Object)
                    ins.Add(Instruction.Create(OpCodes.Castclass, retType.ToTypeDefOrRef()));
            }

            ins.Add(Instruction.Create(OpCodes.Ret));

            body.OptimizeMacros();
            method.Body = body;
        }
    }

    internal class VirtualizedMethod
    {
        public MethodDef Method;
        public int       MethodIndex;
        public byte[]    Bytecode;       // encrypted + opcode-shuffled
        public byte[]    KeyA;           // first 8 bytes of XOR key
        public byte[]    KeyB;           // last  8 bytes, stored XOR'd with hash(KeyA)
        public byte[]    HandlerTable;   // serialized exception handler table (empty if none)
        public int       LocalsCount;
        public bool      IsVoid;
    }
}
