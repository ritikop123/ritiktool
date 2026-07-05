using Avalonia;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Interactivity;

namespace LaitoxxGui.Views;

public partial class SpinnerControl : UserControl
{
    // ── Avalonia properties ──────────────────────────────────────────────────
    public static readonly StyledProperty<int> ValueProperty =
        AvaloniaProperty.Register<SpinnerControl, int>(nameof(Value), defaultValue: 0,
            coerce: (o, v) =>
            {
                var s = (SpinnerControl)o;
                return Math.Max(s.Minimum, Math.Min(s.Maximum, v));
            });

    public static readonly StyledProperty<int> MinimumProperty =
        AvaloniaProperty.Register<SpinnerControl, int>(nameof(Minimum), defaultValue: 0);

    public static readonly StyledProperty<int> MaximumProperty =
        AvaloniaProperty.Register<SpinnerControl, int>(nameof(Maximum), defaultValue: int.MaxValue);

    public static readonly StyledProperty<int> StepProperty =
        AvaloniaProperty.Register<SpinnerControl, int>(nameof(Step), defaultValue: 1);

    public int Value   { get => GetValue(ValueProperty);   set => SetValue(ValueProperty, value); }
    public int Minimum { get => GetValue(MinimumProperty); set => SetValue(MinimumProperty, value); }
    public int Maximum { get => GetValue(MaximumProperty); set => SetValue(MaximumProperty, value); }
    public int Step    { get => GetValue(StepProperty);    set => SetValue(StepProperty, value); }

    public SpinnerControl() => InitializeComponent();

    private void OnMinus(object? sender, RoutedEventArgs e) => Value -= Step;
    private void OnPlus (object? sender, RoutedEventArgs e) => Value += Step;

    private void OnKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Up)   { Value += Step; e.Handled = true; }
        if (e.Key == Key.Down) { Value -= Step; e.Handled = true; }
        if (e.Key == Key.Enter)
        {
            // Parse typed value
            if (sender is TextBox tb && int.TryParse(tb.Text, out int parsed))
                Value = parsed;
            e.Handled = true;
        }
    }
}
