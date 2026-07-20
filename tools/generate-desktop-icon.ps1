param([string]$OutputPath)

Add-Type -AssemblyName System.Drawing
$bitmap = New-Object System.Drawing.Bitmap 256,256
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$graphics.Clear([System.Drawing.Color]::Transparent)
$shield = [System.Drawing.Point[]]@(
    [System.Drawing.Point]::new(128,14), [System.Drawing.Point]::new(224,54),
    [System.Drawing.Point]::new(224,121), [System.Drawing.Point]::new(210,174),
    [System.Drawing.Point]::new(176,218), [System.Drawing.Point]::new(128,248),
    [System.Drawing.Point]::new(80,218), [System.Drawing.Point]::new(46,174),
    [System.Drawing.Point]::new(32,121), [System.Drawing.Point]::new(32,54))
$brush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb(53,199,216))
$graphics.FillPolygon($brush, $shield)
$pen = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(16,34,40)),22
$pen.StartCap = $pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round
$graphics.DrawLines($pen, [System.Drawing.Point[]]@([System.Drawing.Point]::new(72,127),[System.Drawing.Point]::new(108,163),[System.Drawing.Point]::new(186,84)))
$memory = New-Object System.IO.MemoryStream
$bitmap.Save($memory, [System.Drawing.Imaging.ImageFormat]::Png)
$png = $memory.ToArray()
$directory = [System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($OutputPath))
[System.IO.Directory]::CreateDirectory($directory) | Out-Null
$file = [System.IO.File]::Create($OutputPath)
$writer = New-Object System.IO.BinaryWriter $file
$writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]1)
$writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([byte]0); $writer.Write([byte]0)
$writer.Write([uint16]1); $writer.Write([uint16]32); $writer.Write([uint32]$png.Length); $writer.Write([uint32]22)
$writer.Write($png)
$writer.Dispose(); $memory.Dispose(); $pen.Dispose(); $brush.Dispose(); $graphics.Dispose(); $bitmap.Dispose()
