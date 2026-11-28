using System;
using System.IO;
using Glacier.Codec.Gpu.Cli;
using Xunit;

namespace Glacier.Codec.Tests;

public class GpuCliTests
{
    private static readonly object ConsoleLock = new();

    [Fact]
    public void ParseArgs_EmptyAndNull_DefaultsToBench()
    {
        var r1 = Program.ParseArgs(Array.Empty<string>());
        Assert.True(r1.IsSuccess);
        Assert.Equal(CliCommand.Bench, r1.Options.Command);
        Assert.False(r1.Options.PreferAmd);

        var r2 = Program.ParseArgs(null);
        Assert.True(r2.IsSuccess);
        Assert.Equal(CliCommand.Bench, r2.Options.Command);
    }

    [Theory]
    [InlineData("help")]
    [InlineData("--help")]
    [InlineData("-h")]
    [InlineData("/?")]
    [InlineData("HELP")]
    public void ParseArgs_HelpVariants_ReturnsHelpCommand(string arg)
    {
        var result = Program.ParseArgs([arg]);
        Assert.True(result.IsSuccess);
        Assert.Equal(CliCommand.Help, result.Options.Command);
    }

    [Fact]
    public void ParseArgs_InfoAndBenchVariants_ParseCorrectly()
    {
        var info = Program.ParseArgs(["INFO"]);
        Assert.True(info.IsSuccess);
        Assert.Equal(CliCommand.Info, info.Options.Command);

        var benchAmd1 = Program.ParseArgs(["bench", "amd"]);
        Assert.True(benchAmd1.IsSuccess);
        Assert.Equal(CliCommand.Bench, benchAmd1.Options.Command);
        Assert.True(benchAmd1.Options.PreferAmd);

        var benchAmd2 = Program.ParseArgs(["bench-amd"]);
        Assert.True(benchAmd2.IsSuccess);
        Assert.Equal(CliCommand.BenchAmd, benchAmd2.Options.Command);
        Assert.True(benchAmd2.Options.PreferAmd);

        var amd = Program.ParseArgs(["amd"]);
        Assert.True(amd.IsSuccess);
        Assert.Equal(CliCommand.BenchAmd, amd.Options.Command);
    }

    [Fact]
    public void ParseArgs_SearchCommand_ParsesDefaultsAndExplicitOptions()
    {
        var def = Program.ParseArgs(["search"]);
        Assert.True(def.IsSuccess);
        Assert.Equal(CliCommand.Search, def.Options.Command);
        Assert.Equal("blake3", def.Options.Algorithm);
        Assert.Equal(16u, def.Options.DifficultyBits);
        Assert.False(def.Options.PreferD3D12);

        var custom = Program.ParseArgs(["search", "SHA256", "24", "d3d12"]);
        Assert.True(custom.IsSuccess);
        Assert.Equal(CliCommand.Search, custom.Options.Command);
        Assert.Equal("sha256", custom.Options.Algorithm);
        Assert.Equal(24u, custom.Options.DifficultyBits);
        Assert.True(custom.Options.PreferD3D12);
    }

    [Theory]
    [InlineData(new[] { "unknown-cmd" }, "Unknown command")]
    [InlineData(new[] { "search", "md5" }, "Unsupported algorithm")]
    [InlineData(new[] { "search", "blake3", "notanint" }, "Invalid difficulty")]
    [InlineData(new[] { "search", "sha256", "33" }, "Invalid difficulty")]
    [InlineData(new[] { "search", "sha256", "-1" }, "Invalid difficulty")]
    public void ParseArgs_InvalidInputs_ReturnsFailureWithMessage(string[] args, string expectedErrorFragment)
    {
        var result = Program.ParseArgs(args);
        Assert.False(result.IsSuccess);
        Assert.NotNull(result.ErrorMessage);
        Assert.Contains(expectedErrorFragment, result.ErrorMessage);
    }

    [Theory]
    [InlineData(0u, 0x00000000u)]
    [InlineData(1u, 0x80000000u)]
    [InlineData(8u, 0xFF000000u)]
    [InlineData(16u, 0xFFFF0000u)]
    [InlineData(24u, 0xFFFFFF00u)]
    [InlineData(32u, 0xFFFFFFFFu)]
    [InlineData(64u, 0xFFFFFFFFu)]
    public void ComputeDifficultyMask_ReturnsExpectedMask(uint bits, uint expectedMask)
    {
        Assert.Equal(expectedMask, Program.ComputeDifficultyMask(bits));
        Assert.Equal(expectedMask, Program.ComputeDifficultyMask(bits, "sha256"));
    }

    [Theory]
    [InlineData(0u, 0x00000000u)]
    [InlineData(1u, 0x00000080u)]
    [InlineData(4u, 0x000000F0u)]
    [InlineData(8u, 0x000000FFu)]
    [InlineData(12u, 0x0000F0FFu)]
    [InlineData(16u, 0x0000FFFFu)]
    [InlineData(24u, 0x00FFFFFFu)]
    [InlineData(32u, 0xFFFFFFFFu)]
    [InlineData(64u, 0xFFFFFFFFu)]
    public void ComputeBlake3DifficultyMask_ReturnsLittleEndianWordMask(uint bits, uint expectedMask)
    {
        Assert.Equal(expectedMask, Program.ComputeBlake3DifficultyMask(bits));
        Assert.Equal(expectedMask, Program.ComputeDifficultyMask(bits, "blake3"));
        Assert.Equal(expectedMask, Program.ComputeDifficultyMask(bits, "BLAKE3"));
    }

    [Theory]
    [InlineData(new byte[] { 0xFF, 0xFF }, 0u, true)]
    [InlineData(new byte[] { 0x00, 0x00, 0xAB }, 16u, true)]
    [InlineData(new byte[] { 0x00, 0x0F, 0xFF }, 12u, true)]
    [InlineData(new byte[] { 0x00, 0x10, 0x00 }, 12u, false)]
    [InlineData(new byte[] { 0x00, 0x01, 0x00 }, 16u, false)]
    [InlineData(new byte[] { 0x00, 0x00, 0x00, 0x00 }, 32u, true)]
    public void HasLeadingZeroBits_ValidatesByteAndSubBytePrefixes(byte[] hash, uint bits, bool expected)
    {
        Assert.Equal(expected, Program.HasLeadingZeroBits(hash, bits));
    }

    [Fact]
    public void Main_Help_ReturnsZeroAndPrintsUsage()
    {
        lock (ConsoleLock)
        {
            var origOut = Console.Out;
            using var sw = new StringWriter();
            try
            {
                Console.SetOut(sw);
                int exitCode = Program.Main(["--help"]);
                Assert.Equal(0, exitCode);
                string output = sw.ToString();
                Assert.Contains("Usage:", output);
                Assert.Contains("info", output);
                Assert.Contains("search", output);
            }
            finally
            {
                Console.SetOut(origOut);
            }
        }
    }

    [Fact]
    public void Main_InvalidCommand_ReturnsOneAndPrintsErrorToStdErr()
    {
        lock (ConsoleLock)
        {
            var origOut = Console.Out;
            var origErr = Console.Error;
            using var outSw = new StringWriter();
            using var errSw = new StringWriter();
            try
            {
                Console.SetOut(outSw);
                Console.SetError(errSw);
                int exitCode = Program.Main(["bogus-command"]);
                Assert.Equal(1, exitCode);
                Assert.Contains("Unknown command 'bogus-command'", errSw.ToString());
                Assert.Contains("Usage:", outSw.ToString());
            }
            finally
            {
                Console.SetOut(origOut);
                Console.SetError(origErr);
            }
        }
    }

    [Fact]
    public void Main_Info_RunsGracefullyWithoutRequiringGpu()
    {
        lock (ConsoleLock)
        {
            var origOut = Console.Out;
            using var sw = new StringWriter();
            try
            {
                Console.SetOut(sw);
                int exitCode = Program.Main(["info"]);
                Assert.Equal(0, exitCode);
                Assert.Contains("Universal Hardware Nonce Engine", sw.ToString());
            }
            finally
            {
                Console.SetOut(origOut);
            }
        }
    }
}
