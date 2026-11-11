using ProcessArchDemo.Compat;

namespace ProcessArchDemo.Tests;

internal static class ClassifierTests
{
    public static void Register(TestRunner runner)
    {
        runner.Run("Classifier maps native processor architecture values", () =>
        {
            Check.Equal(
                NativeMethods.ImageFileMachineI386,
                ArchitectureClassifier.MachineFromNativeProcessorArchitecture(0),
                "PROCESSOR_ARCHITECTURE_INTEL");
            Check.Equal(
                NativeMethods.ImageFileMachineArmNt,
                ArchitectureClassifier.MachineFromNativeProcessorArchitecture(5),
                "PROCESSOR_ARCHITECTURE_ARM");
            Check.Equal(
                NativeMethods.ImageFileMachineAmd64,
                ArchitectureClassifier.MachineFromNativeProcessorArchitecture(9),
                "PROCESSOR_ARCHITECTURE_AMD64");
            Check.Equal(
                NativeMethods.ImageFileMachineArm64,
                ArchitectureClassifier.MachineFromNativeProcessorArchitecture(12),
                "PROCESSOR_ARCHITECTURE_ARM64");
            Check.Equal(
                NativeMethods.ImageFileMachineUnknown,
                ArchitectureClassifier.MachineFromNativeProcessorArchitecture(0xFFFF),
                "unknown processor architecture");
        });

        runner.Run("Classifier maps PE machine values", () =>
        {
            Check.Equal(
                ProcessArchitecture.X86,
                ArchitectureClassifier.ProcessFromMachine(NativeMethods.ImageFileMachineI386),
                "x86");
            Check.Equal(
                ProcessArchitecture.X64,
                ArchitectureClassifier.ProcessFromMachine(NativeMethods.ImageFileMachineAmd64),
                "x64");
            Check.Equal(
                ProcessArchitecture.Arm32,
                ArchitectureClassifier.ProcessFromMachine(NativeMethods.ImageFileMachineArmNt),
                "arm32");
            Check.Equal(
                ProcessArchitecture.Arm64,
                ArchitectureClassifier.ProcessFromMachine(NativeMethods.ImageFileMachineArm64),
                "arm64");
            Check.Equal(
                ProcessArchitecture.Arm64Ec,
                ArchitectureClassifier.ProcessFromMachine(NativeMethods.ImageFileMachineArm64Ec),
                "arm64ec");
            Check.Equal(
                ProcessArchitecture.Arm64X,
                ArchitectureClassifier.ProcessFromMachine(NativeMethods.ImageFileMachineArm64X),
                "arm64x");
            Check.Equal(
                ProcessArchitecture.Unknown,
                ArchitectureClassifier.ProcessFromMachine(0x1234),
                "unknown machine");
        });

        runner.Run("Classifier refines hybrid PE images", () =>
        {
            Check.Equal(
                ProcessArchitecture.X64,
                ArchitectureClassifier.ClassifyPe(
                    new PeImageInfo(NativeMethods.ImageFileMachineAmd64, false, Array.Empty<string>())),
                "plain AMD64 image");
            Check.Equal(
                ProcessArchitecture.Arm64Ec,
                ArchitectureClassifier.ClassifyPe(
                    new PeImageInfo(
                        NativeMethods.ImageFileMachineAmd64,
                        true,
                        new[] { ".a64xrm" })),
                "AMD64 image with hybrid markers");
            Check.Equal(
                ProcessArchitecture.Arm64,
                ArchitectureClassifier.ClassifyPe(
                    new PeImageInfo(NativeMethods.ImageFileMachineArm64, false, Array.Empty<string>())),
                "plain ARM64 image");
            Check.Equal(
                ProcessArchitecture.Arm64X,
                ArchitectureClassifier.ClassifyPe(
                    new PeImageInfo(
                        NativeMethods.ImageFileMachineArm64,
                        true,
                        new[] { ".hexpthk" })),
                "ARM64 image with hybrid markers");
            Check.Equal(
                ProcessArchitecture.Arm64Ec,
                ArchitectureClassifier.ClassifyPe(
                    new PeImageInfo(
                        NativeMethods.ImageFileMachineArm64Ec,
                        false,
                        Array.Empty<string>())),
                "explicit ARM64EC image");
            Check.Equal(
                ProcessArchitecture.Arm64X,
                ArchitectureClassifier.ClassifyPe(
                    new PeImageInfo(
                        NativeMethods.ImageFileMachineArm64X,
                        false,
                        Array.Empty<string>())),
                "explicit ARM64X image");
        });

        runner.Run("Classifier computes ARM compatibility flags", () =>
        {
            ArmCompatibilityFlags arm64Native = ArchitectureClassifier.GetArmFlags(
                HostArchitecture.Arm64,
                ProcessArchitecture.Arm64);
            Check.True(arm64Native.RunningOnArm, "arm64 host runs on ARM");
            Check.True(arm64Native.IsArmNative, "arm64 process is native");
            Check.False(arm64Native.IsEmulated, "arm64 process is not emulated");

            ArmCompatibilityFlags arm64X = ArchitectureClassifier.GetArmFlags(
                HostArchitecture.Arm64,
                ProcessArchitecture.Arm64X);
            Check.True(arm64X.IsArmNative, "arm64x process is native");
            Check.False(arm64X.IsEmulated, "arm64x process is not emulated");

            ArmCompatibilityFlags arm64Ec = ArchitectureClassifier.GetArmFlags(
                HostArchitecture.Arm64,
                ProcessArchitecture.Arm64Ec);
            Check.True(arm64Ec.IsArmNative, "arm64ec process is native");
            Check.False(arm64Ec.IsEmulated, "arm64ec process is not emulated");

            ArmCompatibilityFlags x64OnArm = ArchitectureClassifier.GetArmFlags(
                HostArchitecture.Arm64,
                ProcessArchitecture.X64);
            Check.False(x64OnArm.IsArmNative, "x64 process is not ARM-native");
            Check.True(x64OnArm.IsEmulated, "x64 process is emulated on ARM64");

            ArmCompatibilityFlags x86OnArm = ArchitectureClassifier.GetArmFlags(
                HostArchitecture.Arm64,
                ProcessArchitecture.X86);
            Check.True(x86OnArm.IsEmulated, "x86 process is emulated on ARM64");

            ArmCompatibilityFlags x86OnX64 = ArchitectureClassifier.GetArmFlags(
                HostArchitecture.X64,
                ProcessArchitecture.X86);
            Check.False(x86OnX64.RunningOnArm, "x64 host is not ARM");
            Check.False(x86OnX64.IsArmNative, "x86 process is not ARM-native");
            Check.False(x86OnX64.IsEmulated, "WOW64 on x64 is not CPU emulation");

            ArmCompatibilityFlags unknownOnArm = ArchitectureClassifier.GetArmFlags(
                HostArchitecture.Arm64,
                ProcessArchitecture.Unknown);
            Check.False(unknownOnArm.IsArmNative, "unknown process is not ARM-native");
            Check.False(unknownOnArm.IsEmulated, "unknown process is not marked emulated");
        });

        runner.Run("Classifier formats machine names", () =>
        {
            Check.Equal("AMD64", ArchitectureClassifier.MachineName(NativeMethods.ImageFileMachineAmd64), "AMD64 name");
            Check.Equal("ARM64", ArchitectureClassifier.MachineName(NativeMethods.ImageFileMachineArm64), "ARM64 name");
            Check.Equal("ARM64EC", ArchitectureClassifier.MachineName(NativeMethods.ImageFileMachineArm64Ec), "ARM64EC name");
            Check.Equal("ARM64X", ArchitectureClassifier.MachineName(NativeMethods.ImageFileMachineArm64X), "ARM64X name");
            Check.Equal("0x1234", ArchitectureClassifier.MachineName(0x1234), "unknown machine name");
        });
    }
}
