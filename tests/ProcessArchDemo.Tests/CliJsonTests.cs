using System.Text.Json;
using ProcessArchDemo.Cli;
using ProcessArchDemo.Compat;

namespace ProcessArchDemo.Tests;

internal static class CliJsonTests
{
    public static void Register(TestRunner runner)
    {
        runner.Run("JSON report has the documented shape", () =>
        {
            var detector = new ProcessArchitectureDetector();
            CompatibilityReport report = detector.Inspect(Environment.ProcessId);
            string json = CliJson.Serialize(detector.Host, new[] { report });

            using JsonDocument document = JsonDocument.Parse(json);
            JsonElement root = document.RootElement;

            Check.Equal(1, root.GetProperty("schema_version").GetInt32(), "schema version");
            Check.Equal(
                detector.Host.Architecture.ToWireName(),
                root.GetProperty("host").GetProperty("arch").GetString(),
                "host arch");
            Check.True(
                root.GetProperty("host").GetProperty("native_machine").GetString() is not null,
                "host native machine");
            Check.Equal(
                detector.Host.DetectionMethod,
                root.GetProperty("host").GetProperty("detection").GetString(),
                "host detection method");

            JsonElement processes = root.GetProperty("processes");
            Check.Equal(1, processes.GetArrayLength(), "process count");

            JsonElement process = processes[0];
            Check.Equal(Environment.ProcessId, process.GetProperty("pid").GetInt32(), "pid");
            Check.Equal(
                report.ProcessArchitecture.ToWireName(),
                process.GetProperty("process_arch").GetString(),
                "process arch");
            Check.Equal(
                report.Confidence.ToWireName(),
                process.GetProperty("confidence").GetString(),
                "confidence");
            Check.Equal(
                report.Reason,
                process.GetProperty("reason").GetString(),
                "reason");
            Check.True(
                process.GetProperty("image_path").GetString() is not null,
                "image path");
        });

        runner.Run("JSON report supports an empty process list", () =>
        {
            var detector = new ProcessArchitectureDetector();
            string json = CliJson.Serialize(detector.Host, Array.Empty<CompatibilityReport>());

            using JsonDocument document = JsonDocument.Parse(json);
            Check.Equal(
                0,
                document.RootElement.GetProperty("processes").GetArrayLength(),
                "empty process array");
        });
    }
}
