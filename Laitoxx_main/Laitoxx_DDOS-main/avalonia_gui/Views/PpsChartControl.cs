using Avalonia;
using Avalonia.Controls;
using Avalonia.Media;
using Avalonia.Threading;
using System.Collections.ObjectModel;
using System.Collections.Specialized;

namespace LaitoxxGui.Views;

/// <summary>
/// Rolling PPS line chart with gradient fill and line glow.
/// Drawn with Avalonia DrawingContext — zero external dependencies.
/// </summary>
public class PpsChartControl : Control
{
    // ── Avalonia property ────────────────────────────────────────────────────
    public static readonly StyledProperty<ObservableCollection<double>> ValuesProperty =
        AvaloniaProperty.Register<PpsChartControl, ObservableCollection<double>>(
            nameof(Values), defaultValue: new());

    public ObservableCollection<double> Values
    {
        get => GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    static PpsChartControl()
    {
        ValuesProperty.Changed.AddClassHandler<PpsChartControl>((c, e) => c.OnValuesChanged(e));
        AffectsRender<PpsChartControl>(ValuesProperty);
    }

    private void OnValuesChanged(AvaloniaPropertyChangedEventArgs e)
    {
        if (e.OldValue is ObservableCollection<double> old)
            old.CollectionChanged -= OnCollectionChanged;
        if (e.NewValue is ObservableCollection<double> nw)
            nw.CollectionChanged += OnCollectionChanged;
    }

    private void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
        => Dispatcher.UIThread.Post(InvalidateVisual, DispatcherPriority.Render);

    // ── Render ───────────────────────────────────────────────────────────────
    public override void Render(DrawingContext ctx)
    {
        var pts = Values;
        double w = Bounds.Width;
        double h = Bounds.Height;
        if (w <= 0 || h <= 0) return;

        // Paddings so axis labels don't clip
        const double padLeft  = 34;
        const double padRight = 8;
        const double padTop   = 10;
        const double padBot   = 4;

        double cw = w - padLeft - padRight;   // chart width
        double ch = h - padTop  - padBot;     // chart height

        // ── Max value (at least 10 so grid looks reasonable) ─────────────────
        double max = pts.Count > 0 ? pts.Max() : 0;
        max = Math.Max(max * 1.15, 10); // 15% headroom

        // ── Colors ──────────────────────────────────────────────────────────
        var gridColor  = Color.FromArgb(18,  255, 255, 255);
        var labelColor = Color.FromArgb(80,  113, 113, 122);
        var lineColor  = Color.FromRgb(16, 185, 129);       // emerald
        var glowColor  = Color.FromArgb(60,  16, 185, 129); // glow layer
        var fillTop    = Color.FromArgb(55,  16, 185, 129);
        var fillBot    = Color.FromArgb(0,   16, 185, 129);

        var gridPen  = new Pen(new SolidColorBrush(gridColor), 1);
        var linePen  = new Pen(new SolidColorBrush(lineColor), 2, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round);
        var glowPen  = new Pen(new SolidColorBrush(glowColor), 6, lineCap: PenLineCap.Round, lineJoin: PenLineJoin.Round);

        var tf = new Typeface("Cascadia Mono, Consolas, monospace");

        // ── Grid lines + Y labels (3 levels) ─────────────────────────────────
        for (int i = 1; i <= 4; i++)
        {
            double frac = (double)i / 4;
            double y    = padTop + ch * (1 - frac);

            // grid line
            ctx.DrawLine(gridPen,
                new Point(padLeft, y),
                new Point(padLeft + cw, y));

            // label
            double val = max * frac;
            string lbl = val >= 1_000_000 ? $"{val/1_000_000:F1}M"
                       : val >= 1000      ? $"{val/1000:F0}k"
                       : $"{val:F0}";

            var ft = new FormattedText(lbl,
                System.Globalization.CultureInfo.InvariantCulture,
                FlowDirection.LeftToRight, tf, 9,
                new SolidColorBrush(labelColor));
            ctx.DrawText(ft, new Point(padLeft - ft.Width - 4, y - ft.Height / 2));
        }

        // ── Nothing to draw yet ───────────────────────────────────────────────
        if (pts.Count < 2) return;

        int n = pts.Count;
        double stepX = cw / (n - 1);

        // ── Helper: (index → Point in chart space) ───────────────────────────
        Point P(int i) => new(
            padLeft + i * stepX,
            padTop  + ch * (1.0 - pts[i] / max));

        // ── Build gradient fill ───────────────────────────────────────────────
        var fillGeo = new StreamGeometry();
        using (var sgc = fillGeo.Open())
        {
            sgc.BeginFigure(new Point(padLeft, padTop + ch), true);
            for (int i = 0; i < n; i++) sgc.LineTo(P(i));
            sgc.LineTo(new Point(padLeft + cw, padTop + ch));
            sgc.EndFigure(true);
        }

        // Gradient fill: emerald → transparent bottom
        var gradBrush = new LinearGradientBrush
        {
            StartPoint = new RelativePoint(0, 0, RelativeUnit.Relative),
            EndPoint   = new RelativePoint(0, 1, RelativeUnit.Relative),
            GradientStops =
            {
                new GradientStop(fillTop, 0.0),
                new GradientStop(fillBot, 1.0),
            }
        };
        ctx.DrawGeometry(gradBrush, null, fillGeo);

        // ── Build line ────────────────────────────────────────────────────────
        var lineGeo = new StreamGeometry();
        using (var sgc = lineGeo.Open())
        {
            sgc.BeginFigure(P(0), false);
            for (int i = 1; i < n; i++) sgc.LineTo(P(i));
        }

        // Glow pass (thick, semi-transparent)
        ctx.DrawGeometry(null, glowPen, lineGeo);
        // Crisp line on top
        ctx.DrawGeometry(null, linePen, lineGeo);

        // ── Latest value label ────────────────────────────────────────────────
        double last = pts[n - 1];
        if (last > 0)
        {
            string valStr = last >= 1000 ? $"{last/1000:F1}k" : $"{last:F0}";
            var ftVal = new FormattedText(valStr,
                System.Globalization.CultureInfo.InvariantCulture,
                FlowDirection.LeftToRight, tf, 10,
                new SolidColorBrush(lineColor));
            var lastPt = P(n - 1);
            ctx.DrawText(ftVal, new Point(
                Math.Min(lastPt.X - ftVal.Width / 2, w - ftVal.Width - 2),
                Math.Max(lastPt.Y - ftVal.Height - 3, padTop)));
        }
    }
}
