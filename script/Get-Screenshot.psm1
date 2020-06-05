<#
    Author: @strontic20
    Website: strontic.com
    Github: github.com/strontic/xcyclopedia
    Adapted from: 
        https://rkeithhill.wordpress.com/2013/10/20/powershell-tidbit-capturing-a-screenshot-with-powershell/
        https://foxdeploy.com/2017/09/09/use-powershell-to-take-automated-screencaps/
    Synopsis: Take screenshot of specified process id.
    License: MIT License; Copyright (c) 2020 strontic
#>

function Get-Screenshot($processid,$save_path) {

    #param ([int]$procesid,[string]$save_path)

$src = @'
using System;
using System.Runtime.InteropServices;

namespace PInvoke
{
    public static class NativeMethods 
    {
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;        // x position of upper-left corner
        public int Top;         // y position of upper-left corner
        public int Right;       // x position of lower-right corner
        public int Bottom;      // y position of lower-right corner
    }
}
'@

    Add-Type -TypeDefinition $src
    Add-Type -AssemblyName System.Drawing

    # Get a process object from which we will get the main window bounds
    $iseProc = Get-Process -id $processid
    $processname = $iseProc.Name

    $time
    $bitmap = $g = $null
    try {
        $rect = new-object PInvoke.RECT
        if ([PInvoke.NativeMethods]::GetWindowRect($iseProc.MainWindowHandle, [ref]$rect))
        {
            $width = $rect.Right - $rect.Left
            $height = $rect.Bottom - $rect.Top
            $bitmap = new-object System.Drawing.Bitmap $width,$height
            $g = [System.Drawing.Graphics]::FromImage($bitmap)
            $g."CopyFromScreen"($rect.Left, $rect.Top, 0, 0, $bitmap.Size, 
                              [System.Drawing.CopyPixelOperation]::SourceCopy)
            #$bitmap.Save("$save_path.bmp")
            $bitmap.Save("$save_path.png",([system.drawing.imaging.imageformat]::Png));
            #$bitmap.Save("$save_path.jpg",([system.drawing.imaging.imageformat]::Jpeg));
        }
    }
    finally {
        if ($bitmap) { $bitmap.Dispose() }
        if ($g) { $g.Dispose() }
    }

}

Export-ModuleMember -function Get-Screenshot