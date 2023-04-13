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


unit wpcap.IOUtils;

interface

uses Winapi.Windows;

///<summary>
/// Returns the size of the specified file in bytes.
///</summary>
///<param name="FileName">
/// The name of the file for which to retrieve the size.
///</param>
///<returns>
/// The size of the specified file in bytes.
///</returns>
///<remarks>
/// This function returns the size of the specified file in bytes. 
/// If the specified file does not exist or cannot be accessed, an exception will be raised.
///</remarks>
function FileGetSize(const FileName: string): Int64;

implementation


function FileGetSize(const FileName: string): Int64;
var FileAttributesEx: WIN32_FILE_ATTRIBUTE_DATA;
    OldMode         : Cardinal;
    Size            : ULARGE_INTEGER;
begin
  Result  := -1;
  OldMode := SetErrorMode(SEM_FAILCRITICALERRORS);
  try
    if GetFileAttributesEx(PChar(FileName), GetFileExInfoStandard, @FileAttributesEx) then
    begin
      Size.LowPart  := FileAttributesEx.nFileSizeLow;
      Size.HighPart := FileAttributesEx.nFileSizeHigh;
      Result        := Size.QuadPart;
    end;
  finally
    SetErrorMode(OldMode);
  end;
end;

end.
