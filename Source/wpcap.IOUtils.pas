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
