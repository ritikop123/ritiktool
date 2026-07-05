using Avalonia.Controls;
using LaitoxxGui.ViewModels;

namespace LaitoxxGui.Views;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
    }

    protected override void OnOpened(EventArgs e)
    {
        base.OnOpened(e);
        // Inject storage provider so the ViewModel can open file pickers
        if (DataContext is MainWindowViewModel vm)
            vm.StorageProvider = StorageProvider;
    }

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (DataContext is MainWindowViewModel vm)
        {
            // Wire StorageProvider in case DataContext is set after Opened
            vm.StorageProvider = StorageProvider;

            vm.LogEntries.CollectionChanged += (_, _) =>
                Avalonia.Threading.Dispatcher.UIThread.Post(() =>
                {
                    var scroll = this.FindControl<ScrollViewer>("LogScroll");
                    scroll?.ScrollToEnd();
                });
        }
    }
}
