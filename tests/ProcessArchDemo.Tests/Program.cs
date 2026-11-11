using System.Runtime.InteropServices;
using ProcessArchDemo.Tests;

Console.WriteLine("WindowsProcArchDetector checks");
Console.WriteLine(
    $"Runtime: {RuntimeInformation.RuntimeIdentifier} / " +
    $"OS={RuntimeInformation.OSArchitecture} / Process={RuntimeInformation.ProcessArchitecture}");
Console.WriteLine();

var runner = new TestRunner();
ClassifierTests.Register(runner);
PeImageInspectorTests.Register(runner);
DetectorTests.Register(runner);
CliJsonTests.Register(runner);
return runner.Finish();
