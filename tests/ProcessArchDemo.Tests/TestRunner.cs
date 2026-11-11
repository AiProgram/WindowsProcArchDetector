namespace ProcessArchDemo.Tests;

internal sealed class TestRunner
{
    private readonly List<string> _failures = new();
    private int _passed;
    private int _skipped;

    public void Run(string name, Action test)
    {
        try
        {
            test();
            _passed++;
            Console.WriteLine($"[PASS] {name}");
        }
        catch (SkipTestException ex)
        {
            _skipped++;
            Console.WriteLine($"[SKIP] {name} - {ex.Message}");
        }
        catch (Exception ex)
        {
            _failures.Add(name);
            Console.WriteLine($"[FAIL] {name}");
            Console.WriteLine(ex);
        }
    }

    public int Finish()
    {
        Console.WriteLine();
        Console.WriteLine(
            $"Checks: passed={_passed}, failed={_failures.Count}, skipped={_skipped}");

        if (_failures.Count > 0)
        {
            Console.WriteLine("Failed checks:");
            foreach (string failure in _failures)
            {
                Console.WriteLine($"  - {failure}");
            }

            return 1;
        }

        return 0;
    }
}

internal sealed class CheckFailedException : Exception
{
    public CheckFailedException(string message)
        : base(message)
    {
    }
}

internal sealed class SkipTestException : Exception
{
    public SkipTestException(string message)
        : base(message)
    {
    }
}

internal static class Check
{
    public static void Equal<T>(T expected, T actual, string context)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new CheckFailedException(
                $"{context}: expected '{expected}', actual '{actual}'");
        }
    }

    public static void True(bool condition, string context)
    {
        if (!condition)
        {
            throw new CheckFailedException($"{context}: expected true");
        }
    }

    public static void False(bool condition, string context)
    {
        if (condition)
        {
            throw new CheckFailedException($"{context}: expected false");
        }
    }

    public static T NotNull<T>(T? value, string context)
        where T : class
    {
        return value ?? throw new CheckFailedException($"{context}: expected non-null");
    }

    public static void Contains(string value, string expectedSubstring, string context)
    {
        if (!value.Contains(expectedSubstring, StringComparison.Ordinal))
        {
            throw new CheckFailedException(
                $"{context}: expected '{value}' to contain '{expectedSubstring}'");
        }
    }

    public static void Skip(string reason)
    {
        throw new SkipTestException(reason);
    }
}
