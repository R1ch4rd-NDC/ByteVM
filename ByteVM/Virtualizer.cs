using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;
using ByteVM.Core;

namespace ByteVM
{
    public class Virtualizer
    {
        // Skip specific methods without touching anything else.
        public Predicate<MethodDef> ShouldSkip { get; set; }

        // When true, ByteVM.Runtime.dll is embedded inside the output assembly as a
        // resource so the protected app runs without any external DLL next to it.
        // The obfuscator looks for the DLL next to itself, then falls back to cwd.
        public bool SelfContained { get; set; } = true;

        private const string RuntimeAssemblyName = "ByteVM.Runtime";
        private static readonly Version RuntimeVersion = new Version(1, 0, 0, 0);

        public int Run(string inputPath, string outputPath)
        {
            if (!File.Exists(inputPath))
                throw new FileNotFoundException("Assembly not found.", inputPath);

            Console.WriteLine($"[*] Loading: {inputPath}");

            var ctx    = ModuleDef.CreateModuleContext();
            var module = ModuleDefMD.Load(inputPath, ctx);

            var shuffler = new OpcodeShuffler();
            var rng      = new Random();

            // Single-byte XOR key for the decode table stored in __VMData__.
            // Never 0 — an all-zero key would be a no-op.
            byte decodeTableKey = (byte)rng.Next(1, 256);

            var methodTable = new List<IMethod>();
            var fieldTable  = new List<IField>();
            var typeTable   = new List<ITypeDefOrRef>();

            var translator = new MethodVirtualizer(methodTable, fieldTable, typeTable, shuffler);
            var vms        = new List<VirtualizedMethod>();
            int count      = 0;

            foreach (var type in module.GetTypes())
            {
                if (type.IsGlobalModuleType) continue;

                foreach (var method in type.Methods)
                {
                    if (!IsEligible(method)) continue;

                    Console.Write($"  [~] Virtualizing {type.Name}::{method.Name} ... ");

                    try
                    {
                        var (rawBytecode, handlerTable, localsCount) =
                            translator.Virtualize(method);

                        var key       = GenerateKey(rng, 16);
                        var encrypted = XorEncrypt(rawBytecode, key);

                        // Split key into two halves.
                        // KeyB is stored as keyB[i] = key[8+i] ^ hashA, meaning you need
                        // KeyA to recover KeyB — they're interdependent in storage.
                        byte hashA = 0;
                        for (int k = 0; k < 8; k++) hashA ^= key[k];

                        var keyA = new byte[8];
                        var keyB = new byte[8];
                        Array.Copy(key, 0, keyA, 0, 8);
                        for (int k = 0; k < 8; k++)
                            keyB[k] = (byte)(key[8 + k] ^ hashA);

                        bool isVoid = method.ReturnType.ElementType == ElementType.Void;

                        vms.Add(new VirtualizedMethod
                        {
                            Method       = method,
                            MethodIndex  = count,
                            Bytecode     = encrypted,
                            KeyA         = keyA,
                            KeyB         = keyB,
                            HandlerTable = handlerTable,
                            LocalsCount  = localsCount,
                            IsVoid       = isVoid,
                        });

                        count++;
                        int handlers = handlerTable.Length > 0
                            ? (handlerTable.Length - 4) / 24 : 0;
                        Console.WriteLine(
                            $"OK ({rawBytecode.Length}b raw → {encrypted.Length}b enc" +
                            (handlers > 0 ? $", {handlers} handler(s)" : "") + ")");
                    }
                    catch (NotSupportedException ex)
                    {
                        Console.WriteLine($"SKIP ({ex.Message})");
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"ERROR: {ex.Message}");
                    }
                }
            }

            if (count == 0)
            {
                Console.WriteLine("[!] No methods were virtualised.");
                return 0;
            }

            Console.WriteLine($"[*] Injecting runtime data ({count} methods) ...");

            byte[] runtimeDllBytes = null;
            if (SelfContained)
            {
                string runtimePath = FindRuntimeDll();
                if (runtimePath != null)
                {
                    runtimeDllBytes = File.ReadAllBytes(runtimePath);
                    Console.WriteLine(
                        $"[*] Self-contained: embedding {Path.GetFileName(runtimePath)} " +
                        $"({runtimeDllBytes.Length} bytes)");
                }
                else
                {
                    Console.WriteLine("[!] SelfContained=true but ByteVM.Runtime.dll not found — skipping embed.");
                }
            }

            var injector = new RuntimeInjector(module);
            injector.Inject(
                methodTable, fieldTable, typeTable, vms,
                shuffler.DecodeTable,
                decodeTableKey,
                RuntimeAssemblyName, RuntimeVersion,
                runtimeDllBytes);

            Console.WriteLine($"[*] Writing: {outputPath}");

            var opts = new ModuleWriterOptions(module);
            opts.Logger = DummyLogger.NoThrowInstance;
            module.Write(outputPath, opts);

            Console.WriteLine($"[+] Done. {count} method(s) virtualised.");
            if (!SelfContained)
                Console.WriteLine($"[!] Distribute '{RuntimeAssemblyName}.dll' alongside the output.");

            return count;
        }

        private bool IsEligible(MethodDef method)
        {
            if (!method.HasBody)                     return false;
            if (method.Body.Instructions.Count == 0) return false;
            if (method.IsConstructor)                return false;
            if (method.IsAbstract)                   return false;
            if (method.ImplMap != null)               return false; // P/Invoke
            if (ShouldSkip != null && ShouldSkip(method)) return false;
            return true;
        }

        // Look for ByteVM.Runtime.dll next to this DLL first, then in the working directory.
        private static string FindRuntimeDll()
        {
            string here = Path.Combine(
                Path.GetDirectoryName(typeof(Virtualizer).Assembly.Location),
                "ByteVM.Runtime.dll");
            if (File.Exists(here)) return here;

            string cwd = Path.Combine(Directory.GetCurrentDirectory(), "ByteVM.Runtime.dll");
            if (File.Exists(cwd)) return cwd;

            return null;
        }

        private static byte[] GenerateKey(Random rng, int length)
        {
            var key = new byte[length];
            rng.NextBytes(key);
            // Zero bytes XOR with nothing — replace them so every byte of the key matters.
            for (int i = 0; i < key.Length; i++)
                if (key[i] == 0) key[i] = (byte)rng.Next(1, 256);
            return key;
        }

        private static byte[] XorEncrypt(byte[] data, byte[] key)
        {
            var result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            return result;
        }
    }
}
