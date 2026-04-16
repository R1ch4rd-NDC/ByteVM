# ByteVM

A simple .NET virtual machine obfuscator that translates CIL method bodies into custom VM bytecode.

## How it works

ByteVM replaces the CIL instructions of each eligible method with a small stub that calls a built-in interpreter (`VMInterpreter.Execute`). The original logic is compiled into a private bytecode format and stored encrypted inside the assembly. At runtime, the interpreter decodes and executes the bytecode on a stack-based VM.

**Before protection:**
```csharp
static int Factorial(int n)
{
    if (n <= 1) return 1;
    return n * Factorial(n - 1);
}
```

**After protection:**
```csharp
static int Factorial(int n)
{
    object[] array = new object[] { n };
    int num = (-1052036627 * 19) & 0;
    byte[] decodeTable = __VMData__.DecodeTable;
    VMInterpreter.Execute(
        __VMData__.Bytecodes[18], __VMData__.LocalCounts[18], array,
        __VMData__.KeyPartsA[18], __VMData__.KeyPartsB[18],
        __VMData__.DecodeTable, __VMData__.HandlerTables[18],
        __VMData__.Methods, __VMData__.Fields, __VMData__.Types);
}
```

## Project structure

```
ByteVM/
├── ByteVM/               # Obfuscator library
│   ├── Virtualizer.cs        # Entry point — iterates methods and drives the pipeline
│   └── Core/
│       ├── MethodVirtualizer.cs  # CIL → VM bytecode translation
│       ├── BytecodeBuilder.cs    # Byte buffer builder with branch-slot patching
│       ├── OpcodeShuffler.cs     # Per-build random opcode permutation
│       └── RuntimeInjector.cs    # Injects __VMData__, stubs, and the module initializer
├── ByteVM.Runtime/       # Runtime library (embedded into protected assemblies)
│   ├── VMOpCode.cs           # VM instruction set enum
│   └── VMInterpreter.cs      # Stack-based bytecode interpreter
├── ByteVM.Console/       # Command-line frontend
└── Tests/                # Test targets
```

## Usage

### CLI

```
ByteVM.Console.exe <input.exe> [output.exe]
```

If no output path is given, the protected file is saved as `<name>.protected.exe` next to the input.

You can also drag and drop an assembly onto the executable to protect it interactively.

### API

```csharp
var v = new ByteVM.Virtualizer();

// Skip specific methods if needed
v.ShouldSkip = m => m.Name == "Main";

// Embed ByteVM.Runtime.dll inside the output (default: true)
v.SelfContained = true;

int count = v.Run("MyApp.exe", "MyApp.protected.exe");
```

## Limitations

- Methods with `filter` exception handlers are skipped (not yet supported)
- Constructors (`.ctor` / `.cctor`) are skipped
- Abstract and P/Invoke methods are skipped
- The interpreter uses reflection for all method calls, so protected code runs slower than native CIL

## Disclaimer

This tool is provided for **educational and research purposes only** — understanding .NET internals, studying obfuscation techniques, and protecting software you own or have explicit authorization to protect.

**You must not use ByteVM to:**
- Obfuscate malware, ransomware, or any software intended to cause harm
- Bypass license checks or DRM on software you do not own
- Violate any applicable law or regulation in your jurisdiction
- Infringe on the intellectual property rights of others

The author(s) of this project accept **no liability whatsoever** for any damage, legal consequence, or misuse arising from the use of this software. By using ByteVM, you agree that you are solely responsible for how you use it and that any consequences - legal or otherwise - are entirely your own.

## License

MIT License

Copyright (c) 2026 Richard-NDC

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
