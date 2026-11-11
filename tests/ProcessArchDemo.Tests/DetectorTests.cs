using System.Diagnostics;
using System.Runtime.InteropServices;
using ProcessArchDemo.Compat;

namespace ProcessArchDemo.Tests;

internal static class DetectorTests
{
    public static void Register(TestRunner runner)
    {
        runner.Run("Host detection reports the OS architecture", () =>
        {
            HostInfo host = ProcessArchitectureDetector.DetectHost();

            Check.True(host.Architecture != HostArchitecture.Unknown, "host architecture is known");
            Check.True(host.NativeMachine != 0, "native machine is not zero");
            Check.True(host.DetectionMethod.Length > 0, "detection method is recorded");
            Check.Equal(
                ToHostArchitecture(RuntimeInformation.OSArchitecture),
                host.Architecture,
                "host architecture should match RuntimeInformation.OSArchitecture");
        });

        runner.Run("Current process report matches RuntimeInformation", () =>
        {
            var detector = new ProcessArchitectureDetector();
            CompatibilityReport report = detector.Inspect(Environment.ProcessId);

            Check.Equal(Environment.ProcessId, report.ProcessId, "PID");
            Check.Equal(
                detector.Host.Architecture,
                report.HostArchitecture,
                "report host architecture");
            Check.Equal(
                ToProcessArchitecture(RuntimeInformation.ProcessArchitecture),
                report.ProcessArchitecture,
                "current process architecture");
            Check.Equal(Confidence.High, report.Confidence, "PE evidence should give high confidence");
            Check.True(report.PeMachine is not null, "PE machine is populated");
            Check.True(report.ImagePath is not null, "image path is populated");
            Check.True(File.Exists(report.ImagePath), "image path exists");
            Check.Contains(report.Reason, "host=", "reason contains host evidence");
            Check.Contains(report.Reason, "PE=", "reason contains PE evidence");

            ArmCompatibilityFlags expectedFlags = ArchitectureClassifier.GetArmFlags(
                detector.Host.Architecture,
                report.ProcessArchitecture);
            Check.Equal(expectedFlags.RunningOnArm, report.RunningOnArm, "running_on_arm");
            Check.Equal(expectedFlags.IsArmNative, report.IsArmNative, "is_arm_native");
            Check.Equal(expectedFlags.IsEmulated, report.IsEmulated, "is_emulated");
        });

        runner.Run("Inspection of a nonexistent PID is safe", () =>
        {
            var detector = new ProcessArchitectureDetector();
            CompatibilityReport report = detector.Inspect(int.MaxValue);

            Check.Equal(ProcessArchitecture.Unknown, report.ProcessArchitecture, "unknown architecture");
            Check.Equal(Confidence.Low, report.Confidence, "low confidence");
            Check.Contains(report.Reason, "OpenProcess", "reason contains the open failure");
        });

        runner.Run("x86 SysWOW64 process is detected", () =>
        {
            if (!Environment.Is64BitOperatingSystem)
            {
                Check.Skip("not a 64-bit Windows installation");
            }

            string systemDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string cmdPath = Path.Combine(systemDirectory, "SysWOW64", "cmd.exe");
            if (!File.Exists(cmdPath))
            {
                Check.Skip("SysWOW64\\cmd.exe is not present");
            }

            var startInfo = new ProcessStartInfo
            {
                FileName = cmdPath,
                Arguments = "/c \"ping -n 11 127.0.0.1 >nul\"",
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden,
            };

            using Process child = Check.NotNull(Process.Start(startInfo), "start x86 cmd.exe");
            try
            {
                var detector = new ProcessArchitectureDetector();
                CompatibilityReport report = detector.Inspect(child.Id);

                Check.Equal(ProcessArchitecture.X86, report.ProcessArchitecture, "x86 process architecture");
                Check.True(report.IsWow64, "x86 process is WOW64");
                Check.False(report.IsArmNative, "x86 process is not ARM-native");
                Check.Equal(
                    detector.Host.Architecture is HostArchitecture.Arm64 or HostArchitecture.Arm32,
                    report.IsEmulated,
                    "is_emulated follows the host");
                Check.Equal(Confidence.High, report.Confidence, "x86 process should have high confidence");
            }
            finally
            {
                try
                {
                    if (!child.HasExited)
                    {
                        child.Kill(entireProcessTree: true);
                    }
                }
                catch (InvalidOperationException)
                {
                }
                catch (System.ComponentModel.Win32Exception)
                {
                }
            }
        });
    }

    private static HostArchitecture ToHostArchitecture(Architecture architecture) => architecture switch
    {
        Architecture.X86 => HostArchitecture.X86,
        Architecture.X64 => HostArchitecture.X64,
        Architecture.Arm => HostArchitecture.Arm32,
        Architecture.Arm64 => HostArchitecture.Arm64,
        _ => HostArchitecture.Unknown,
    };

    private static ProcessArchitecture ToProcessArchitecture(Architecture architecture) => architecture switch
    {
        Architecture.X86 => ProcessArchitecture.X86,
        Architecture.X64 => ProcessArchitecture.X64,
        Architecture.Arm => ProcessArchitecture.Arm32,
        Architecture.Arm64 => ProcessArchitecture.Arm64,
        _ => ProcessArchitecture.Unknown,
    };
}
