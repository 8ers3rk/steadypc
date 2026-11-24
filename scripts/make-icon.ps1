Add-Type -AssemblyName System.Drawing

$size = 256
$bitmap = New-Object System.Drawing.Bitmap($size, $size)
$graphics = [System.Drawing.Graphics]::FromImage($bitmap)
$graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$graphics.Clear([System.Drawing.Color]::Transparent)

$background = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(22, 42, 52))
$graphics.FillRectangle($background, 0, 0, $size, $size)

$accent = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(73, 184, 169))
$graphics.FillEllipse($accent, 48, 44, 160, 160)

$pen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 18)
$pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$pen.EndCap = [System.Drawing.Drawing2D.LineCap]::Round
$points = @(
  (New-Object System.Drawing.Point(88, 132)),
  (New-Object System.Drawing.Point(118, 162)),
  (New-Object System.Drawing.Point(172, 102))
)
$graphics.DrawLines($pen, $points)

$graphics.Dispose()
$pen.Dispose()
$accent.Dispose()
$background.Dispose()

$icon = [System.Drawing.Icon]::FromHandle($bitmap.GetHicon())
$stream = [System.IO.File]::Create((Join-Path (Get-Location) 'electron\icon.ico'))
$icon.Save($stream)
$stream.Dispose()
$icon.Dispose()
$bitmap.Dispose()

Write-Host 'electron/icon.ico created'
