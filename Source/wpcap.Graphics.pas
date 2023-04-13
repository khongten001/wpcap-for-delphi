//*************************************************************
//                        WPCAP FOR DELPHI                    *
//				                                        			      *
//                     Freeware Library                       *
//                       For Delphi 10.4                      *
//                            by                              *
//                     Alessandro Mancini                     *
//				                                        			      *
//*************************************************************
{LICENSE:
THIS SOFTWARE IS PROVIDED TO YOU "AS IS" WITHOUT WARRANTY OF ANY KIND,
EITHER EXPRESSED OR IMPLIED INCLUDING BUT NOT LIMITED TO THE APPLIED
WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.
YOU ASSUME THE ENTIRE RISK AS TO THE ACCURACY AND THE USE OF THE SOFTWARE
AND ALL OTHER RISK ARISING OUT OF THE USE OR PERFORMANCE OF THIS SOFTWARE
AND DOCUMENTATION. PRODUCTIONS DOES NOT WARRANT THAT THE SOFTWARE IS ERROR-FREE
OR WILL OPERATE WITHOUT INTERRUPTION. THE SOFTWARE IS NOT DESIGNED, INTENDED
OR LICENSED FOR USE IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE CONTROLS,
INCLUDING WITHOUT LIMITATION, THE DESIGN, CONSTRUCTION, MAINTENANCE OR
OPERATION OF NUCLEAR FACILITIES, AIRCRAFT NAVIGATION OR COMMUNICATION SYSTEMS,
AIR TRAFFIC CONTROL, AND LIFE SUPPORT OR WEAPONS SYSTEMS. PRODUCTIONS SPECIFICALLY
DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF FITNESS FOR SUCH PURPOSE.

You may use/change/modify the component under 1 conditions:
1. In your application, add credits to "WPCAP FOR DELPHI"
{*******************************************************************************}


unit wpcap.Graphics;

interface

uses vcl.Graphics,System.SysUtils,WinApi.Windows;

/// <summary>
/// Determines the font color (black or white) based on the given background color.
/// </summary>
/// <param name="ABackgroundColor">The background color to check.</param>
/// <returns>The font color (black or white) that has good contrast with the background color.</returns>
function GetFontColor(const ABackgroundColor: TColor): TColor;
function ColorToHTMLColor(const aColor:TColor):String;

implementation

function ColorToHTMLColor(const aColor:TColor):String;
begin
  Result := Format('#%.2x%.2x%.2x', [GetRValue(aColor), GetGValue(aColor), GetBValue(aColor)]);
end;

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
