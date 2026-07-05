using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using LaitoxxGui.ViewModels;
using LaitoxxGui.Views;

namespace LaitoxxGui;

public partial class App : Application
{
    private MainWindow? _mainWindow;
    private TrayIcon?   _trayIcon;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var vm = new MainWindowViewModel();
            _mainWindow = new MainWindow { DataContext = vm };
            desktop.MainWindow = _mainWindow;
            SetupTray(desktop);

            _mainWindow.Closing += (_, e) =>
            {
                e.Cancel = true;
                _mainWindow.Hide();
            };
        }
        base.OnFrameworkInitializationCompleted();
    }

    private void SetupTray(IClassicDesktopStyleApplicationLifetime desktop)
    {
        _trayIcon = new TrayIcon { ToolTipText = "LAITOXX DDoS", IsVisible = true };

        var menu    = new NativeMenu();
        var show    = new NativeMenuItem("Show");
        show.Click += (_, _) => ShowWindow();
        menu.Add(show);
        menu.Add(new NativeMenuItemSeparator());
        var exit    = new NativeMenuItem("Exit");
        exit.Click += (_, _) => { _trayIcon.IsVisible = false; desktop.Shutdown(); };
        menu.Add(exit);

        _trayIcon.Menu    = menu;
        _trayIcon.Clicked += (_, _) => ShowWindow();
    }

    private void ShowWindow()
    {
        if (_mainWindow == null) return;
        _mainWindow.Show();
        _mainWindow.WindowState = WindowState.Normal;
        _mainWindow.Activate();
    }
}
