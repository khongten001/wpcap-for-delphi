unit wpcap.StrUtils;

interface

uses WinApi.Windows,WinSock,System.SysUtils,DateUtils;

/// <summary>
/// This function takes a byte array representing the IPv6 address in the TIPv6Header structure, and returns
/// a string representing the address in standard format separated by colons. The function also deletes sections of
/// consecutive zeros so as to make the address more compact.
/// </summary>
function IPv6AddressToString(const Address: array of Byte): string;

/// <summary>
/// The function "intToIPV4" takes a 32-bit unsigned integer value, which represents an IPv4 address in binary format, 
/// and converts it into a string in dotted decimal notation.
/// 
/// In IPv4, an address is represented by a 32-bit binary number, which is divided into four 8-bit sections. 
/// Each section is then converted into a decimal number and separated by a dot. This notation is called dotted decimal notation.

/// The function accomplishes this by first extracting the four sections of the 32-bit integer using bit masking and bit shifting operations, 
/// and then converting each section into a string using the IntToStr function. The four strings are then concatenated with dots in between to form the final dotted decimal string.
/// </summary>
function intToIPV4(ip: LongWord): string;

/// <summary>
/// The function MACAddrToStr takes an array of bytes representing a MAC address and converts it into a string representation in the format of "XX:XX:XX:XX:XX:XX", 
/// where each "XX" represents a two-digit hexadecimal number corresponding to each byte in the array. The resulting string is returned by the function.
/// </summary>
function MACAddrToStr(const MACAddr: array of Byte): string;

 /// <summary>
///  The TimevalToString function takes a timeval structure as input and converts it to a string in the format seconds.milliseconds. 
///  The timeval structure is commonly used in C programming to represent a time value with microsecond resolution. The function extracts the tv_sec field, 
///  which represents the number of seconds since the Epoch, and the tv_usec field, which represents the number of microseconds within the current second. The two values are then combined to produce a string with the format seconds.milliseconds.
 /// </summary>
function TimevalToString(tv: timeval): string;

function SizeToStr(aSize: int64) : String;

implementation

function IPv6AddressToString(const Address: array of Byte): string;
var
  i, MaxZeroStart, MaxZeroLen, ZeroStart, ZeroLen: Integer;
  HexStr: string;
  IsZero, InZeroSeq: Boolean;
begin
  MaxZeroStart := -1;
  MaxZeroLen := 0;
  ZeroStart := -1;
  ZeroLen := 0;
  InZeroSeq := False;
  for i := 0 to Length(Address) - 1 do
  begin
    IsZero := (Address[i] = 0);
    if IsZero then
    begin
      if not InZeroSeq then
      begin
        InZeroSeq := True;
        ZeroStart := i;
        ZeroLen := 1;
      end
      else
        Inc(ZeroLen);
    end
    else
    begin
      if InZeroSeq then
      begin
        InZeroSeq := False;
        if ZeroLen > MaxZeroLen then
        begin
          MaxZeroLen := ZeroLen;
          MaxZeroStart := ZeroStart;
        end;
      end;
    end;
  end;
  if InZeroSeq and (ZeroLen > MaxZeroLen) then
  begin
    MaxZeroLen := ZeroLen;
    MaxZeroStart := ZeroStart;
  end;
  HexStr := '';
  for i := 0 to Length(Address) - 1 do
  begin
    if (MaxZeroStart >= 0) and (i >= MaxZeroStart) and (i < MaxZeroStart + MaxZeroLen) then
    begin
      if i = MaxZeroStart then
        HexStr := HexStr + ':';
      continue;
    end;
    HexStr := HexStr + IntToHex(Address[i], 2) + ':';
  end;
  SetLength(HexStr, Length(HexStr) - 1);
  Result := StringReplace(HexStr, ':0:', '::', [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '::0', '::', [rfReplaceAll, rfIgnoreCase]);
  Result := StringReplace(Result, '0::', '::', [rfReplaceAll, rfIgnoreCase]);
end;

function intToIPV4(ip: LongWord): string;
begin
  Result := IntToStr(ip and $FF) + '.' +
            IntToStr((ip shr 8) and $FF) + '.' +
            IntToStr((ip shr 16) and $FF) + '.' +
            IntToStr((ip shr 24) and $FF); 
end;

function MACAddrToStr(const MACAddr: array of Byte): string;
begin
  Result := Format('%.2x:%.2x:%.2x:%.2x:%.2x:%.2x',
                   [MACAddr[0], MACAddr[1], MACAddr[2],
                    MACAddr[3], MACAddr[4], MACAddr[5]]);
end;


function TimevalToString(tv: timeval): string;
var dt: TDateTime;
begin
  dt := UnixToDateTime(tv.tv_sec, False);
  Result := FormatDateTime('yyyy-mm-dd hh:nn:ss.zzz', dt);
end;

function SizeToStr(aSize: Int64): string;
const KiloByte = 1024;
      MegaByte = KiloByte * KiloByte;
      GigaByte = MegaByte * KiloByte;
begin

  if aSize < KiloByte then
    Result := Format('%d byte', [aSize])
  else if aSize < MegaByte then
    Result := Format('%.2f KB', [aSize / KiloByte])
  else if aSize < GigaByte then
    Result := Format('%.2f MB', [aSize / MegaByte])
  else 
    Result := Format('%.2f GB', [aSize / GigaByte])
end;



end.
