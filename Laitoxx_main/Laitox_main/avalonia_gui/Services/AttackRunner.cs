using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using LaitoxxGui.Models;

namespace LaitoxxGui.Services;

public record AttackConfig(
    string Method,
    string Target,
    int Port,
    int Threads,
    int Duration,
    int Rps,
    string? Proxy,
    bool Unsafe = false
);

public class AttackRunner : IDisposable
{
    private Process? _proc;
    private CancellationTokenSource? _cts;

    public event Action<AttackStat>? StatReceived;
    public event Action<string>? LogLine;
    public event Action? Finished;

    public bool IsRunning => _proc is { HasExited: false };

    /// <summary>
    /// Finds console_app.py relative to this executable.
    /// exe is in gui/, console_app.py is also in gui/.
    /// </summary>
    private static string FindConsoleApp()
    {
        // Try same directory as the exe
        var exeDir = AppContext.BaseDirectory;
        var candidate = Path.Combine(exeDir, "console_app.py");
        if (File.Exists(candidate)) return candidate;

        // Dev mode: avalonia_gui/bin/Debug/net6.0/ -> up 4 levels -> gui/
        var dir = new DirectoryInfo(exeDir);
        for (int i = 0; i < 6; i++)
        {
            if (dir == null) break;
            var c = Path.Combine(dir.FullName, "console_app.py");
            if (File.Exists(c)) return c;
            dir = dir.Parent;
        }
        throw new FileNotFoundException("console_app.py not found relative to exe.");
    }

    private static string FindPython()
    {
        // Prefer python3, fall back to python
        foreach (var name in new[] { "python3", "python" })
        {
            var result = TryWhich(name);
            if (result != null) return result;
        }
        return "python"; // last resort
    }

    private static string? TryWhich(string name)
    {
        try
        {
            var p = Process.Start(new ProcessStartInfo
            {
                FileName = "where",
                Arguments = name,
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (p == null) return null;
            var line = p.StandardOutput.ReadLine();
            p.WaitForExit();
            return string.IsNullOrWhiteSpace(line) ? null : line.Trim();
        }
        catch { return null; }
    }

    public void Start(AttackConfig cfg)
    {
        Stop(); // stop any previous

        var script = FindConsoleApp();
        var python = FindPython();
        var args = BuildArgs(cfg, script);

        var psi = new ProcessStartInfo
        {
            FileName               = python,
            Arguments              = args,
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            UseShellExecute        = false,
            CreateNoWindow         = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding  = Encoding.UTF8,
        };

        // Force Python unbuffered output — belt AND suspenders with reconfigure()
        psi.Environment["PYTHONUNBUFFERED"] = "1";
        psi.Environment["PYTHONIOENCODING"] = "utf-8";

        _proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
        _cts  = new CancellationTokenSource();
        var token = _cts.Token;

        _proc.Exited += (_, _) => Finished?.Invoke();
        _proc.Start();

        // Read stdout on background thread — parse JSON lines
        Task.Run(() => ReadLoop(_proc.StandardOutput, token, isStdErr: false), token);
        // Read stderr on separate thread — surface as log lines
        Task.Run(() => ReadLoop(_proc.StandardError,  token, isStdErr: true),  token);
    }

    private void ReadLoop(System.IO.StreamReader reader, CancellationToken ct, bool isStdErr)
    {
        try
        {
            string? line;
            while ((line = reader.ReadLine()) != null && !ct.IsCancellationRequested)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;

                if (!isStdErr && line.StartsWith('{'))
                {
                    // JSON stats line
                    try
                    {
                        var stat = JsonSerializer.Deserialize<AttackStatRaw>(line);
                        if (stat != null)
                            StatReceived?.Invoke(new AttackStat(
                                stat.t, stat.pps, stat.packets, stat.remaining, stat.status ?? ""));
                    }
                    catch { LogLine?.Invoke(line); }
                }
                else
                {
                    LogLine?.Invoke(line);
                }
            }
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            LogLine?.Invoke($"[reader error] {ex.Message}");
        }
    }

    public void Stop()
    {
        _cts?.Cancel();
        try { _proc?.Kill(entireProcessTree: true); } catch { }
        _proc?.Dispose();
        _proc = null;
        _cts?.Dispose();
        _cts = null;
    }

    public void Dispose() => Stop();

    private static string BuildArgs(AttackConfig cfg, string scriptPath)
    {
        // -u = unbuffered (extra safety on top of PYTHONUNBUFFERED env var)
        var sb = new StringBuilder();
        sb.Append($"-u \"{scriptPath}\"");
        sb.Append($" --method {cfg.Method}");
        sb.Append($" --target {cfg.Target}");
        sb.Append($" --port {cfg.Port}");
        sb.Append($" --threads {cfg.Threads}");
        sb.Append($" --duration {cfg.Duration}");
        sb.Append($" --rps {cfg.Rps}");
        if (!string.IsNullOrWhiteSpace(cfg.Proxy))
        {
            // When the value is a .txt file path, pass --proxy-file so the Python
            // layer loads every line and distributes proxies across threads.
            bool isFile = cfg.Proxy.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)
                          && File.Exists(cfg.Proxy);
            if (isFile)
                sb.Append($" --proxy-file \"{cfg.Proxy}\"");
            else
                sb.Append($" --proxy \"{cfg.Proxy}\"");
        }
        if (cfg.Unsafe)
            sb.Append(" --unsafe");
        sb.Append(" --json --interval 0.5");
        return sb.ToString();
    }

    // JSON DTO — matches console_app.py --json output keys
    private record AttackStatRaw(
        [property: JsonPropertyName("t")]         double  t,
        [property: JsonPropertyName("pps")]       double  pps,
        [property: JsonPropertyName("packets")]   long    packets,
        [property: JsonPropertyName("remaining")] double  remaining,
        [property: JsonPropertyName("status")]    string? status
    );
}
