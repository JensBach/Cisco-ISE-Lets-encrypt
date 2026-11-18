using System.Globalization;
using System.Text.RegularExpressions;

namespace CiscoIseLetsEncrypt.Ise;

/// <summary>
/// ISE returns dates in Java <c>Date.toString()</c> style, e.g. "Tue Feb 03 10:15:30 CET 2026".
/// </summary>
public static partial class IseDateParser
{
    private static readonly Dictionary<string, TimeSpan> Zones = new(StringComparer.OrdinalIgnoreCase)
    {
        ["UTC"] = TimeSpan.Zero, ["GMT"] = TimeSpan.Zero, ["Z"] = TimeSpan.Zero,
        ["WET"] = TimeSpan.Zero, ["WEST"] = TimeSpan.FromHours(1),
        ["CET"] = TimeSpan.FromHours(1), ["CEST"] = TimeSpan.FromHours(2),
        ["EET"] = TimeSpan.FromHours(2), ["EEST"] = TimeSpan.FromHours(3),
        ["EST"] = TimeSpan.FromHours(-5), ["EDT"] = TimeSpan.FromHours(-4),
        ["CST"] = TimeSpan.FromHours(-6), ["CDT"] = TimeSpan.FromHours(-5),
        ["MST"] = TimeSpan.FromHours(-7), ["MDT"] = TimeSpan.FromHours(-6),
        ["PST"] = TimeSpan.FromHours(-8), ["PDT"] = TimeSpan.FromHours(-7),
    };

    [GeneratedRegex(@"^\w{3}\s+(?<mon>\w{3})\s+(?<day>\d{1,2})\s+(?<time>\d{2}:\d{2}:\d{2})\s+(?<zone>[A-Za-z]+)\s+(?<year>\d{4})$")]
    private static partial Regex JavaDate();

    public static DateTimeOffset? TryParse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return null;

        var trimmed = value.Trim();
        var m = JavaDate().Match(trimmed);
        if (m.Success)
        {
            var text = $"{m.Groups["day"].Value.PadLeft(2, '0')} {m.Groups["mon"].Value} {m.Groups["year"].Value} {m.Groups["time"].Value}";
            if (DateTime.TryParseExact(text, "dd MMM yyyy HH:mm:ss", CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
            {
                var offset = Zones.GetValueOrDefault(m.Groups["zone"].Value, TimeSpan.Zero);
                return new DateTimeOffset(dt, offset).ToUniversalTime();
            }
        }

        if (DateTimeOffset.TryParse(trimmed, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dto))
            return dto.ToUniversalTime();

        return null;
    }
}
