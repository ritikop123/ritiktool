using System.Collections.ObjectModel;
using System.Reactive.Linq;
using System.Windows.Input;
using ReactiveUI;
using Avalonia.Platform.Storage;
using LaitoxxGui.Models;
using LaitoxxGui.Services;

namespace LaitoxxGui.ViewModels;

public class MainWindowViewModel : ReactiveObject, IDisposable
{
    // ── Form fields ──────────────────────────────────────────────────────────
    private string _target   = "";
    private int    _port     = 443;
    private int    _threads  = 8;
    private int    _duration = 60;
    private int    _rps      = 0;
    private string _proxy    = "";
    private bool   _unsafe  = false;
    private AttackMethod? _selectedMethod;
    private string _selectedCategory = "L7 Bypass";

    // ── PoO state ────────────────────────────────────────────────────────────
    private string _pooStatus      = "Unverified";
    private string _pooStatusColor = "#71717a";
    private bool   _pooVerified    = false;

    public string Target   { get => _target;   set => this.RaiseAndSetIfChanged(ref _target, value); }
    public int    Port     { get => _port;     set => this.RaiseAndSetIfChanged(ref _port, value); }
    public int    Threads  { get => _threads;  set => this.RaiseAndSetIfChanged(ref _threads, value); }
    public int    Duration { get => _duration; set => this.RaiseAndSetIfChanged(ref _duration, value); }
    public int    Rps      { get => _rps;      set => this.RaiseAndSetIfChanged(ref _rps, value); }

    /// <summary>
    /// Single proxy URL (socks5://...) OR path to a .txt file with one proxy per line.
    /// When the value ends with .txt the runner passes --proxy-file so the Python layer
    /// distributes proxies across threads automatically.
    /// </summary>
    public string Proxy    { get => _proxy;    set => this.RaiseAndSetIfChanged(ref _proxy, value); }

    public bool Unsafe
    {
        get => _unsafe;
        set
        {
            this.RaiseAndSetIfChanged(ref _unsafe, value);
            if (value) { PooStatus = "Bypassed (--unsafe)"; PooStatusColor = "#f59e0b"; PooVerified = true; }
            else       { PooStatus = "Unverified";          PooStatusColor = "#71717a"; PooVerified = false; }
        }
    }

    public string PooStatus      { get => _pooStatus;      set => this.RaiseAndSetIfChanged(ref _pooStatus, value); }
    public string PooStatusColor { get => _pooStatusColor; set => this.RaiseAndSetIfChanged(ref _pooStatusColor, value); }
    public bool   PooVerified    { get => _pooVerified;    set => this.RaiseAndSetIfChanged(ref _pooVerified, value); }

    public AttackMethod? SelectedMethod
    {
        get => _selectedMethod;
        set => this.RaiseAndSetIfChanged(ref _selectedMethod, value);
    }
    public string SelectedCategory
    {
        get => _selectedCategory;
        set { this.RaiseAndSetIfChanged(ref _selectedCategory, value); RefreshMethods(); }
    }

    public ObservableCollection<string>       Categories { get; } = new();
    public ObservableCollection<AttackMethod> Methods    { get; } = new();

    // ── Status ───────────────────────────────────────────────────────────────
    private bool   _isRunning   = false;
    private double _currentPps  = 0;
    private long   _totalPkts   = 0;
    private double _remaining   = 0;
    private double _progressPct = 0;
    private string _statusText  = "Idle";
    private string _statusColor = "#71717a";

    public bool   IsRunning   { get => _isRunning;   set => this.RaiseAndSetIfChanged(ref _isRunning, value); }
    public double CurrentPps  { get => _currentPps;  set => this.RaiseAndSetIfChanged(ref _currentPps, value); }
    public long   TotalPkts   { get => _totalPkts;   set => this.RaiseAndSetIfChanged(ref _totalPkts, value); }
    public double Remaining   { get => _remaining;   set => this.RaiseAndSetIfChanged(ref _remaining, value); }
    public double ProgressPct { get => _progressPct; set => this.RaiseAndSetIfChanged(ref _progressPct, value); }
    public string StatusText  { get => _statusText;  set => this.RaiseAndSetIfChanged(ref _statusText, value); }
    public string StatusColor { get => _statusColor; set => this.RaiseAndSetIfChanged(ref _statusColor, value); }

    // ── Formatted helpers ────────────────────────────────────────────────────
    public string PpsFormatted  => CurrentPps >= 1000 ? $"{CurrentPps/1000:F1}k" : $"{CurrentPps:F0}";
    public string PktsFormatted => TotalPkts  >= 1_000_000 ? $"{TotalPkts/1_000_000.0:F2}M"
                                 : TotalPkts  >= 1000      ? $"{TotalPkts/1000.0:F1}k"
                                 : $"{TotalPkts}";
    public string EtaFormatted  => Remaining  >= 3600 ? $"{Remaining/3600:F0}h"
                                 : Remaining  >= 60   ? $"{Remaining/60:F0}m {Remaining%60:F0}s"
                                 : $"{Remaining:F0}s";

    // ── Log ──────────────────────────────────────────────────────────────────
    public ObservableCollection<LogEntry> LogEntries { get; } = new();

    // ── Chart data (custom PpsChartControl) ──────────────────────────────────
    public ObservableCollection<double> ChartValues { get; } = new();

    // ── Commands ─────────────────────────────────────────────────────────────
    public ICommand StartCmd            { get; }
    public ICommand StopCmd             { get; }
    public ICommand VerifyOwnershipCmd  { get; }
    public ICommand BrowseProxyFileCmd  { get; }

    // ── Services ─────────────────────────────────────────────────────────────
    private readonly AttackRunner _runner = new();

    // Injected from MainWindow code-behind after window is shown
    public IStorageProvider? StorageProvider { get; set; }

    public MainWindowViewModel()
    {
        foreach (var cat in AttackMethods.Categories)
            Categories.Add(cat);
        if (!Categories.Contains(_selectedCategory))
            _selectedCategory = Categories.FirstOrDefault() ?? "";
        RefreshMethods();

        StartCmd = ReactiveCommand.Create(StartAttack,
            this.WhenAnyValue(x => x.IsRunning).Select(r => !r));
        StopCmd  = ReactiveCommand.Create(StopAttack,
            this.WhenAnyValue(x => x.IsRunning));
        VerifyOwnershipCmd = ReactiveCommand.Create(OpenPoOInstructions);
        BrowseProxyFileCmd = ReactiveCommand.Create(BrowseProxyFile);

        _runner.StatReceived += OnStat;
        _runner.LogLine      += OnLog;
        _runner.Finished     += OnFinished;

        // Pre-fill with zeros so the chart has a baseline
        for (int i = 0; i < 60; i++) ChartValues.Add(0);
    }

    private void RefreshMethods()
    {
        Methods.Clear();
        foreach (var m in AttackMethods.GetAvailable().Where(m => m.Category == _selectedCategory))
            Methods.Add(m);
        SelectedMethod = Methods.FirstOrDefault();
    }

    public void StartAttack()
    {
        if (SelectedMethod is null || string.IsNullOrWhiteSpace(Target)) return;

        foreach (var i in Enumerable.Range(0, ChartValues.Count)) ChartValues[i] = 0;
        LogEntries.Clear();
        IsRunning   = true;
        StatusText  = "Running";
        StatusColor = "#ef4444";
        ProgressPct = 0;

        var proxyValue = string.IsNullOrWhiteSpace(Proxy) ? null : Proxy.Trim();

        _runner.Start(new AttackConfig(
            SelectedMethod.Code, Target.Trim(), Port,
            Threads, Duration, Rps,
            proxyValue,
            Unsafe: Unsafe));
    }

    public void StopAttack()
    {
        _runner.Stop();
        IsRunning   = false;
        StatusText  = "Stopped";
        StatusColor = "#ef4444";
    }

    private async void BrowseProxyFile()
    {
        if (StorageProvider is null) return;

        var options = new FilePickerOpenOptions
        {
            Title = "Select proxy list (.txt)",
            AllowMultiple = false,
            FileTypeFilter = new[]
            {
                new FilePickerFileType("Text files") { Patterns = new[] { "*.txt" } },
                new FilePickerFileType("All files")  { Patterns = new[] { "*" } },
            }
        };

        var files = await StorageProvider.OpenFilePickerAsync(options);
        if (files is { Count: > 0 })
            Proxy = files[0].Path.LocalPath;
    }

    private void OnStat(AttackStat s)
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            CurrentPps  = s.Pps;
            TotalPkts   = s.Packets;
            Remaining   = s.Remaining;
            ProgressPct = Duration > 0 ? Math.Min(100, s.T / Duration * 100) : 0;

            this.RaisePropertyChanged(nameof(PpsFormatted));
            this.RaisePropertyChanged(nameof(PktsFormatted));
            this.RaisePropertyChanged(nameof(EtaFormatted));

            // Rolling chart: remove oldest, append new
            if (ChartValues.Count >= 120) ChartValues.RemoveAt(0);
            ChartValues.Add(s.Pps);

            if (s.Status is "done" or "Stopped")
            {
                IsRunning   = false;
                StatusText  = "Done";
                StatusColor = "#ef4444";
            }
        });
    }

    private void OnLog(string line)
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            LogEntries.Add(new LogEntry(line));
            if (LogEntries.Count > 300) LogEntries.RemoveAt(0);

            // PoO status detection: parse [PoO] lines emitted by the Python layer
            if (line.Contains("[PoO]"))
            {
                if (line.Contains("ownership verified") || line.Contains("already verified"))
                {
                    PooVerified    = true;
                    PooStatus      = "Verified ✓";
                    PooStatusColor = "#ef4444";
                }
                else if (line.Contains("not verified") || line.Contains("Verification required"))
                {
                    PooVerified    = false;
                    PooStatus      = "Unverified";
                    PooStatusColor = "#ef4444";
                }
            }
        });
    }

    private void OnFinished()
    {
        Avalonia.Threading.Dispatcher.UIThread.Post(() =>
        {
            if (IsRunning) { IsRunning = false; StatusText = "Finished"; StatusColor = "#ef4444"; }
        });
    }

    public void OpenPoOInstructions()
    {
        if (string.IsNullOrWhiteSpace(Target))
        {
            OnLog("[PoO] Enter a target first.");
            return;
        }

        bool isDomain = Target.Trim().Contains('.');
        string method = isDomain ? "DNS TXT" : "reverse-connect";

        OnLog($"[PoO] Verification required for {Target.Trim()}");
        OnLog($"[PoO] Method: {method}");
        if (isDomain)
        {
            OnLog("[PoO] Add a DNS TXT record:  laitoxx-poo.<domain>  →  <token>");
            OnLog("[PoO] Use the TUI (option 8 → D) to generate the token and verify.");
        }
        else
        {
            OnLog("[PoO] Run from the target server:");
            OnLog("[PoO]   curl \"http://<this-machine-IP>:<port>/verify?token=<token>\"");
            OnLog("[PoO] Use the TUI (option 8 → R) to start the listener and get the exact command.");
        }
        OnLog("[PoO] Or enable --unsafe / --i-know-what-im-doing to skip ownership checks.");
    }

    public void Dispose() => _runner.Dispose();
}

public record LogEntry(string Raw)
{
    public string Text  => Raw;
    public string Color => Raw.Contains("ERROR", StringComparison.OrdinalIgnoreCase) ? "#ef4444"
                         : Raw.Contains("WARN",  StringComparison.OrdinalIgnoreCase) ? "#f59e0b"
                         : Raw.Contains("[LAITOXX]")                                 ? "#ef4444"
                         : "#52525b";
}
