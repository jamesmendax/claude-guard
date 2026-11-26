using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace ClaudeGuardNative
{
    internal enum GuardIconState
    {
        Ready,
        Warning,
        Blocked
    }

    internal static class AppIcons
    {
        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyIcon(IntPtr handle);

        [DllImport("gdi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteObject(IntPtr hObject);

        private static System.Windows.Media.Color WpfLedColor(GuardIconState state)
        {
            switch (state)
            {
                case GuardIconState.Warning:
                    return System.Windows.Media.Color.FromRgb(245, 158, 11);
                case GuardIconState.Blocked:
                    return System.Windows.Media.Color.FromRgb(239, 68, 68);
                default:
                    return System.Windows.Media.Color.FromRgb(16, 185, 129);
            }
        }

        private static System.Drawing.Color DrawingLedColor(GuardIconState state)
        {
            switch (state)
            {
                case GuardIconState.Warning:
                    return System.Drawing.Color.FromArgb(255, 245, 158, 11);
                case GuardIconState.Blocked:
                    return System.Drawing.Color.FromArgb(255, 239, 68, 68);
                default:
                    return System.Drawing.Color.FromArgb(255, 34, 197, 94);
            }
        }

        /// <summary>
        /// Pure WPF vector Option A (Aperture Gate) mark for title bar and headers.
        /// Returns both the Viewbox and the LED Ellipse so state color can switch live.
        /// </summary>
        internal static Viewbox CreateBrandMark(double size, GuardIconState state, out Ellipse ledDot)
        {
            var canvas = new Canvas { Width = 256, Height = 256 };

            var bg = new System.Windows.Shapes.Rectangle
            {
                Width = 240,
                Height = 240,
                RadiusX = 54,
                RadiusY = 54,
                Fill = new SolidColorBrush(System.Windows.Media.Color.FromRgb(21, 23, 28))
            };
            Canvas.SetLeft(bg, 8);
            Canvas.SetTop(bg, 8);
            canvas.Children.Add(bg);

            var rim = new System.Windows.Shapes.Rectangle
            {
                Width = 234,
                Height = 234,
                RadiusX = 51,
                RadiusY = 51,
                Stroke = new SolidColorBrush(System.Windows.Media.Color.FromRgb(47, 52, 64)),
                StrokeThickness = 4
            };
            Canvas.SetLeft(rim, 11);
            Canvas.SetTop(rim, 11);
            canvas.Children.Add(rim);

            var arc = new Path
            {
                Data = Geometry.Parse("M 172,82 A 60,60 0 1 0 172,174"),
                Stroke = new SolidColorBrush(System.Windows.Media.Color.FromRgb(245, 246, 248)),
                StrokeThickness = 26,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round
            };
            canvas.Children.Add(arc);

            ledDot = new Ellipse
            {
                Width = 44,
                Height = 44,
                Fill = new SolidColorBrush(WpfLedColor(state))
            };
            Canvas.SetLeft(ledDot, 176 - 22);
            Canvas.SetTop(ledDot, 128 - 22);
            canvas.Children.Add(ledDot);

            return new Viewbox
            {
                Width = size,
                Height = size,
                Stretch = Stretch.Uniform,
                Child = canvas
            };
        }

        internal static void UpdateBrandLed(Ellipse ledDot, GuardIconState state)
        {
            if (ledDot != null)
                ledDot.Fill = new SolidColorBrush(WpfLedColor(state));
        }

        /// <summary>
        /// Crisp uniform 15x15 vector navigation icons matching the approved Swiss Grid sidebar.
        /// </summary>
        internal static UIElement CreateNavIcon(string kind)
        {
            var canvas = new Canvas { Width = 16, Height = 16 };
            var stroke = new SolidColorBrush(System.Windows.Media.Color.FromRgb(75, 81, 98));
            if (kind == "overview")
            {
                AddRect(canvas, 2, 2, 5, 5, 1.2, stroke);
                AddRect(canvas, 9, 2, 5, 5, 1.2, stroke);
                AddRect(canvas, 2, 9, 5, 5, 1.2, stroke);
                AddRect(canvas, 9, 9, 5, 5, 1.2, stroke);
            }
            else if (kind == "exit")
            {
                var globe = new Ellipse { Width = 12, Height = 12, Stroke = stroke, StrokeThickness = 1.5 };
                Canvas.SetLeft(globe, 2);
                Canvas.SetTop(globe, 2);
                canvas.Children.Add(globe);
                canvas.Children.Add(new Path
                {
                    Data = Geometry.Parse("M 2.2,8 H 13.8 M 8,2 A 8.5,8.5 0 0 1 8,14 M 8,2 A 8.5,8.5 0 0 0 8,14"),
                    Stroke = stroke,
                    StrokeThickness = 1.4
                });
            }
            else if (kind == "hygiene")
            {
                canvas.Children.Add(new Path
                {
                    Data = Geometry.Parse("M 2.5,4.8 H 13.5 M 5.5,4.8 V 3.2 A 1,1 0 0 1 6.5,2.2 H 9.5 A 1,1 0 0 1 10.5,3.2 V 4.8 M 4,4.8 L 4.7,12.8 A 1.2,1.2 0 0 0 5.9,13.9 H 10.1 A 1.2,1.2 0 0 0 11.3,12.8 L 12,4.8"),
                    Stroke = stroke,
                    StrokeThickness = 1.5,
                    StrokeStartLineCap = PenLineCap.Round,
                    StrokeEndLineCap = PenLineCap.Round,
                    StrokeLineJoin = PenLineJoin.Round
                });
            }
            else
            {
                // Precision 3-slider hardware icon for System & Maintenance
                AddSliderRow(canvas, 4.5, 5.5, stroke);
                AddSliderRow(canvas, 8.5, 10.5, stroke);
                AddSliderRow(canvas, 12.5, 6.5, stroke);
            }

            return new Viewbox
            {
                Width = 15,
                Height = 15,
                Stretch = Stretch.Uniform,
                Child = canvas
            };
        }

        private static void AddRect(Canvas canvas, double x, double y, double w, double h, double r, System.Windows.Media.Brush stroke)
        {
            var rect = new System.Windows.Shapes.Rectangle
            {
                Width = w,
                Height = h,
                RadiusX = r,
                RadiusY = r,
                Stroke = stroke,
                StrokeThickness = 1.5
            };
            Canvas.SetLeft(rect, x);
            Canvas.SetTop(rect, y);
            canvas.Children.Add(rect);
        }

        private static void AddSliderRow(Canvas canvas, double y, double knobX, System.Windows.Media.Brush stroke)
        {
            canvas.Children.Add(new Line
            {
                X1 = 2.5,
                Y1 = y,
                X2 = 13.5,
                Y2 = y,
                Stroke = stroke,
                StrokeThickness = 1.5,
                StrokeStartLineCap = PenLineCap.Round,
                StrokeEndLineCap = PenLineCap.Round
            });
            var knob = new Ellipse
            {
                Width = 3.6,
                Height = 3.6,
                Fill = new SolidColorBrush(System.Windows.Media.Color.FromRgb(239, 239, 242)),
                Stroke = stroke,
                StrokeThickness = 1.5
            };
            Canvas.SetLeft(knob, knobX - 1.8);
            Canvas.SetTop(knob, y - 1.8);
            canvas.Children.Add(knob);
        }

        internal static Bitmap RenderApertureGateBitmap(int size, GuardIconState state)
        {
            int scale = size <= 64 ? 4 : 2;
            int hi = size * scale;
            using (var src = new Bitmap(hi, hi, System.Drawing.Imaging.PixelFormat.Format32bppArgb))
            {
                using (Graphics g = Graphics.FromImage(src))
                {
                    g.SmoothingMode = SmoothingMode.HighQuality;
                    g.PixelOffsetMode = PixelOffsetMode.HighQuality;
                    g.CompositingQuality = CompositingQuality.HighQuality;
                    g.Clear(System.Drawing.Color.Transparent);

                    float k = hi / 256f;
                    using (GraphicsPath bgPath = CreateRoundRect(8f * k, 8f * k, 240f * k, 240f * k, 54f * k))
                    using (var bgBrush = new SolidBrush(System.Drawing.Color.FromArgb(255, 21, 23, 28)))
                        g.FillPath(bgBrush, bgPath);

                    using (GraphicsPath rimPath = CreateRoundRect(11f * k, 11f * k, 234f * k, 234f * k, 51f * k))
                    using (var rimPen = new System.Drawing.Pen(System.Drawing.Color.FromArgb(255, 47, 52, 64), 4f * k))
                        g.DrawPath(rimPen, rimPath);

                    float cx = 133f * k;
                    float cy = 128f * k;
                    float rad = 60f * k;
                    float strokeW = (size <= 24 ? 27f : 25f) * k;
                    using (var arcPen = new System.Drawing.Pen(System.Drawing.Color.FromArgb(255, 245, 246, 248), strokeW))
                    {
                        arcPen.StartCap = LineCap.Round;
                        arcPen.EndCap = LineCap.Round;
                        g.DrawArc(arcPen, cx - rad, cy - rad, rad * 2f, rad * 2f, 50f, 260f);
                    }

                    float lr = (size <= 32 ? 23f : 20f) * k;
                    float lx = 176f * k;
                    float ly = 128f * k;
                    using (var ledBrush = new SolidBrush(DrawingLedColor(state)))
                        g.FillEllipse(ledBrush, lx - lr, ly - lr, lr * 2f, lr * 2f);
                }

                var dst = new Bitmap(size, size, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
                using (Graphics dg = Graphics.FromImage(dst))
                {
                    dg.InterpolationMode = InterpolationMode.HighQualityBicubic;
                    dg.SmoothingMode = SmoothingMode.HighQuality;
                    dg.PixelOffsetMode = PixelOffsetMode.HighQuality;
                    dg.DrawImage(src, 0, 0, size, size);
                }
                return dst;
            }
        }

        internal static Icon CreateTrayIcon(GuardIconState state)
        {
            using (Bitmap bmp = RenderApertureGateBitmap(32, state))
            {
                IntPtr hIcon = bmp.GetHicon();
                try
                {
                    using (Icon temp = Icon.FromHandle(hIcon))
                        return (Icon)temp.Clone();
                }
                finally
                {
                    DestroyIcon(hIcon);
                }
            }
        }

        internal static ImageSource CreateWindowIconSource(GuardIconState state)
        {
            using (Bitmap bmp = RenderApertureGateBitmap(64, state))
            {
                IntPtr hBitmap = bmp.GetHbitmap();
                try
                {
                    BitmapSource source = Imaging.CreateBitmapSourceFromHBitmap(
                        hBitmap,
                        IntPtr.Zero,
                        Int32Rect.Empty,
                        BitmapSizeOptions.FromEmptyOptions());
                    source.Freeze();
                    return source;
                }
                finally
                {
                    DeleteObject(hBitmap);
                }
            }
        }

        private static GraphicsPath CreateRoundRect(float x, float y, float w, float h, float r)
        {
            float d = r * 2f;
            var path = new GraphicsPath();
            path.AddArc(x, y, d, d, 180f, 90f);
            path.AddArc(x + w - d, y, d, d, 270f, 90f);
            path.AddArc(x + w - d, y + h - d, d, d, 0f, 90f);
            path.AddArc(x, y + h - d, d, d, 90f, 90f);
            path.CloseFigure();
            return path;
        }
    }
}
