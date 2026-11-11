using System.Buffers.Binary;
using ProcessArchDemo.Compat;

namespace ProcessArchDemo.Tests;

internal static class PeImageInspectorTests
{
    public static void Register(TestRunner runner)
    {
        runner.Run("PE reader reads machine and hybrid section names", () =>
        {
            string path = PeFixtureBuilder.Write(
                NativeMethods.ImageFileMachineAmd64,
                optionalHeaderSize: 0,
                ".text",
                ".a64xrm");
            try
            {
                Check.True(
                    PeImageInspector.TryRead(path, out PeImageInfo info, out string? error),
                    $"PE read should succeed: {error}");
                Check.Equal(NativeMethods.ImageFileMachineAmd64, info.Machine, "PE machine");
                Check.True(info.HasHybridMetadata, "hybrid metadata should be detected");
                Check.Equal(1, info.HybridSections.Count, "hybrid section count");
                Check.True(
                    info.HybridSections.Contains(".a64xrm", StringComparer.OrdinalIgnoreCase),
                    "hybrid section list");
                Check.Equal(
                    ProcessArchitecture.Arm64Ec,
                    ArchitectureClassifier.ClassifyPe(info),
                    "AMD64 + hybrid classified as arm64ec");
            }
            finally
            {
                PeFixtureBuilder.Delete(path);
            }
        });

        runner.Run("PE reader honors SizeOfOptionalHeader", () =>
        {
            string path = PeFixtureBuilder.Write(
                NativeMethods.ImageFileMachineArm64,
                optionalHeaderSize: 0xE0,
                ".text",
                ".hexpthk");
            try
            {
                Check.True(
                    PeImageInspector.TryRead(path, out PeImageInfo info, out string? error),
                    $"PE read should succeed: {error}");
                Check.Equal(NativeMethods.ImageFileMachineArm64, info.Machine, "PE machine");
                Check.True(info.HasHybridMetadata, "hybrid metadata should be detected");
                Check.True(
                    info.HybridSections.Contains(".hexpthk", StringComparer.OrdinalIgnoreCase),
                    "section table should start after the optional header");
            }
            finally
            {
                PeFixtureBuilder.Delete(path);
            }
        });

        runner.Run("PE reader detects section names case-insensitively", () =>
        {
            string path = PeFixtureBuilder.Write(
                NativeMethods.ImageFileMachineArm64,
                optionalHeaderSize: 0,
                ".A64XRM");
            try
            {
                Check.True(
                    PeImageInspector.TryRead(path, out PeImageInfo info, out string? error),
                    $"PE read should succeed: {error}");
                Check.True(info.HasHybridMetadata, "uppercase section name should match");
            }
            finally
            {
                PeFixtureBuilder.Delete(path);
            }
        });

        runner.Run("PE reader rejects a non-PE file", () =>
        {
            var data = new byte[0x80];
            string path = PeFixtureBuilder.WriteRaw(data);
            try
            {
                Check.False(
                    PeImageInspector.TryRead(path, out _, out string? error),
                    "non-PE file should be rejected");
                Check.Contains(Check.NotNull(error, "error text"), "MZ", "error should mention MZ");
            }
            finally
            {
                PeFixtureBuilder.Delete(path);
            }
        });

        runner.Run("PE reader rejects a truncated e_lfanew", () =>
        {
            var data = new byte[0x40];
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0, 2), 0x5A4D);
            BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(0x3C, 4), 0x1000);
            string path = PeFixtureBuilder.WriteRaw(data);
            try
            {
                Check.False(
                    PeImageInspector.TryRead(path, out _, out string? error),
                    "truncated PE file should be rejected");
                Check.Contains(
                    Check.NotNull(error, "error text"),
                    "e_lfanew",
                    "error should mention e_lfanew");
            }
            finally
            {
                PeFixtureBuilder.Delete(path);
            }
        });

        runner.Run("PE reader rejects IMAGE_FILE_MACHINE_UNKNOWN", () =>
        {
            string path = PeFixtureBuilder.Write(0);
            try
            {
                Check.False(
                    PeImageInspector.TryRead(path, out _, out string? error),
                    "unknown machine should be rejected");
                Check.Contains(
                    Check.NotNull(error, "error text"),
                    "UNKNOWN",
                    "error should mention UNKNOWN");
            }
            finally
            {
                PeFixtureBuilder.Delete(path);
            }
        });
    }
}
