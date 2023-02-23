unit wpcap.BufferUtils;

interface
uses System.SysUtils;

function BytesToArray(const Bytes: array of Byte): TBytes;

implementation


function BytesToArray(const Bytes: array of Byte): TBytes;
var I: Integer;
begin
  SetLength(Result, Length(Bytes));
  for I := Low(Bytes) to High(Bytes) do
    Result[I] := Bytes[I];
end;

end.
