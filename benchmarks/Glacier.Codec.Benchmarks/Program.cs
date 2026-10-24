namespace Glacier.Codec.Benchmarks;

using System;
using System.Linq;
using BenchmarkDotNet.Running;

public static class Program
{
    public static int Main(string[] args)
    {
        Console.WriteLine("================================================================================");
        Console.WriteLine("     GLACIER.CODEC BENCHMARK & FLEET CERTIFICATION SUITE (.NET 10 / AOT)        ");
        Console.WriteLine("================================================================================");

        bool strict = args.Contains("--strict") || args.Contains("--assert-zero-alloc");
        if (args.Contains("--fast") || args.Contains("--direct") || args.Contains("--verify") || strict)
        {
            return DirectBenchmarkRunner.RunAll(strict);
        }

        Console.WriteLine("\n[Running BenchmarkDotNet Switcher]");
        string[] benchmarkArgs = args.Where(a => a != "--benchmark").ToArray();
        BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(benchmarkArgs);
        return 0;
    }
}
