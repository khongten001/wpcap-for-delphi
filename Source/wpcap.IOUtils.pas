unit wpcap.IOUtils;

interface

uses Winapi.Windows;

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
