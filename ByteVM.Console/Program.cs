using System;
using System.IO;

namespace ByteVM.Console
{
    internal class Program
    {
        static int Main(string[] args)
        {
            PrintBanner();

            if (args.Length == 0)
            {
                // Interactive mode: wait for drag-and-drop / paste
                System.Console.ForegroundColor = ConsoleColor.Yellow;
                System.Console.WriteLine("Drag and drop an assembly here (or type a path) and press Enter:");
                System.Console.ResetColor();
                string input = System.Console.ReadLine()?.Trim().Trim('"');
                if (string.IsNullOrWhiteSpace(input))
                {
                    Error("No input provided.");
                    return 1;
                }
                return Protect(input);
            }

            // CLI mode: first arg is the assembly path, optional second arg is output path
            return Protect(args[0], args.Length > 1 ? args[1] : null);
        }

        static int Protect(string inputPath, string outputPath = null)
        {
            inputPath = inputPath.Trim().Trim('"');

            if (!File.Exists(inputPath))
            {
                Error($"File not found: {inputPath}");
                return 1;
            }

            if (outputPath == null)
            {
                string dir  = Path.GetDirectoryName(inputPath);
                string name = Path.GetFileNameWithoutExtension(inputPath);
                string ext  = Path.GetExtension(inputPath);
                outputPath  = Path.Combine(dir, name + ".protected" + ext);
            }

            try
            {
                var v = new global::ByteVM.Virtualizer();
                int count = v.Run(inputPath, outputPath);

                if (count > 0)
                {
                    System.Console.ForegroundColor = ConsoleColor.Green;
                    System.Console.WriteLine($"\n  Output: {outputPath}");
                    System.Console.ResetColor();
                }
            }
            catch (Exception ex)
            {
                Error(ex.ToString());
                return 1;
            }

            if (System.Console.IsInputRedirected) return 0;
            System.Console.WriteLine("\nPress any key to exit...");
            try { System.Console.ReadKey(true); } catch { }
            return 0;
        }

        static void PrintBanner()
        {
            System.Console.ForegroundColor = ConsoleColor.Cyan;
            System.Console.WriteLine(@"
  ██████╗ ██╗   ██╗████████╗███████╗██╗   ██╗███╗   ███╗
  ██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝██║   ██║████╗ ████║
  ██████╔╝ ╚████╔╝    ██║   █████╗  ██║   ██║██╔████╔██║
  ██╔══██╗  ╚██╔╝     ██║   ██╔══╝  ╚██╗ ██╔╝██║╚██╔╝██║
  ██████╔╝   ██║      ██║   ███████╗ ╚████╔╝ ██║ ╚═╝ ██║
  ╚═════╝    ╚═╝      ╚═╝   ╚══════╝  ╚═══╝  ╚═╝     ╚═╝
  .NET Virtual Machine Obfuscator  v1.0
");
            System.Console.ResetColor();
        }

        static void Error(string msg)
        {
            System.Console.ForegroundColor = ConsoleColor.Red;
            System.Console.WriteLine($"[ERROR] {msg}");
            System.Console.ResetColor();
        }
    }
}
