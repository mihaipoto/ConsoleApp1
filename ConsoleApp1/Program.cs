using System.Diagnostics;
using System.Text;
using System.Text.Json;

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private static async Task Main(string[] args)
    {
        try
        {
            var definitions = await GetDefenderDefinitionsAsync();
            Console.WriteLine($"Definitions version: {definitions.SignatureVersion}");
            Console.WriteLine($"Last updated: {definitions.SignatureLastUpdated}");

            if (args.Length > 0)
            {
                var result = await ScanFolderAsync(args[0]);
                Console.WriteLine($"Scan started: {result.ScanStarted}");
                Console.WriteLine($"Threat detections: {result.Detections.Length}");
                foreach (var detection in result.Detections)
                {
                    Console.WriteLine($"{detection.ThreatName} (ID {detection.ThreatID})");
                }
            }
            else
            {
                Console.WriteLine("Pass a folder path as an argument to scan it.");
            }
        }
        catch (Exception exception)
        {
            Console.Error.WriteLine(exception.Message);
            Environment.ExitCode = 1;
        }
    }

    public static async Task<DefenderDefinitions> GetDefenderDefinitionsAsync()
    {
        const string script = "$ErrorActionPreference = 'Stop'; try { $status = Get-MpComputerStatus; [pscustomobject]@{ SignatureVersion = $status.AntivirusSignatureVersion; SignatureLastUpdated = $status.AntivirusSignatureLastUpdated.ToString('o') } | ConvertTo-Json -Compress } catch { [Console]::Error.WriteLine($_); exit 1 }";
        var json = await RunPowerShellAsync(script);
        return JsonSerializer.Deserialize<DefenderDefinitions>(json, JsonOptions)
            ?? throw new InvalidOperationException("Windows Defender returned no definition status.");
    }

    public static async Task<DefenderScanResult> ScanFolderAsync(string folderPath)
    {
        if (string.IsNullOrWhiteSpace(folderPath) || !Directory.Exists(folderPath))
        {
            throw new DirectoryNotFoundException($"Folder not found: {folderPath}");
        }

        var escapedPath = folderPath.Replace("'", "''");
        var script = $"$ErrorActionPreference = 'Stop'; try {{ $scanStarted = Get-Date; Start-MpScan -ScanType CustomScan -ScanPath '{escapedPath}'; $detections = @(Get-MpThreatDetection | Where-Object {{ $_.InitialDetectionTime -ge $scanStarted }} | Select-Object ThreatID, ThreatName, InitialDetectionTime, ActionSuccess, Resources); [pscustomobject]@{{ ScanStarted = $scanStarted.ToString('o'); Detections = $detections }} | ConvertTo-Json -Compress -Depth 5 }} catch {{ [Console]::Error.WriteLine($_); exit 1 }}";
        var json = await RunPowerShellAsync(script);
        return JsonSerializer.Deserialize<DefenderScanResult>(json, JsonOptions)
            ?? throw new InvalidOperationException("Windows Defender returned no scan results.");
    }

    private static async Task<string> RunPowerShellAsync(string script)
    {
        var startInfo = new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-EncodedCommand");
        startInfo.ArgumentList.Add(Convert.ToBase64String(Encoding.Unicode.GetBytes(script)));

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start Windows PowerShell.");
        var outputTask = process.StandardOutput.ReadToEndAsync();
        var errorTask = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync();
        var output = await outputTask;
        var error = await errorTask;

        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(error) ? output : error);
        }

        return output;
    }

    public sealed record DefenderDefinitions(string SignatureVersion, DateTime SignatureLastUpdated);

    public sealed record DefenderScanResult(DateTime ScanStarted, DefenderThreatDetection[] Detections);

    public sealed record DefenderThreatDetection(
        int ThreatID,
        string ThreatName,
        DateTime InitialDetectionTime,
        bool ActionSuccess,
        string[] Resources);
}
