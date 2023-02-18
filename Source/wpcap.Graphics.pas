unit wpcap.Graphics;

interface

uses vcl.Graphics,System.SysUtils,WinApi.Windows;

/// <summary>
/// Determines the font color (black or white) based on the given background color.
/// </summary>
/// <param name="ABackgroundColor">The background color to check.</param>
/// <returns>The font color (black or white) that has good contrast with the background color.</returns>
function GetFontColor(const ABackgroundColor: TColor): TColor;

implementation


function GetFontColor(const ABackgroundColor: TColor): TColor;
var LRed             : Byte;
    LGreen           : Byte;
    LBlue            : Byte;
    LAverageLuminance: Double;
begin
  // Extract the RGB components from the background color.
  LRed   := GetRValue(ABackgroundColor);
  LGreen := GetGValue(ABackgroundColor);
  LBlue  := GetBValue(ABackgroundColor);

  // Calculate the average luminance of the background color using the formula recommended by the W3C for color contrast.
  // https://www.w3.org/TR/WCAG20/#relativeluminancedef
  // Note: the constant values below are the relative luminance values for red, green, and blue, respectively.
  LAverageLuminance := (0.2126 * LRed + 0.7152 * LGreen + 0.0722 * LBlue) / 255;

  // If the average luminance is less than 0.5, use white font color; otherwise, use black font color.
  if LAverageLuminance < 0.5 then
    Result := clWhite
  else
    Result := clBlack;
end;


end.
