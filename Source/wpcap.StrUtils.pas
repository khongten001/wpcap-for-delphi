unit wpcap.StrUtils;

interface

uses WinApi.Windows,WinSock,System.SysUtils,DateUtils,System.Classes;

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
function BytesToIpV4(const aIp: TBytes): string;
/// <summary>
/// The function MACAddrToStr takes an array of bytes representing a MAC address and converts it into a string representation in the format of "XX:XX:XX:XX:XX:XX", 
/// where each "XX" represents a two-digit hexadecimal number corresponding to each byte in the array. The resulting string is returned by the function.
/// </summary>
function MACAddrToStr(const MACAddr: array of Byte): string;

function MACAddressToString(const AMacAddress: TBytes): string;

 /// <summary>
///  The TimevalToString function takes a timeval structure as input and converts it to a string in the format seconds.milliseconds. 
///  The timeval structure is commonly used in C programming to represent a time value with microsecond resolution. The function extracts the tv_sec field, 
///  which represents the number of seconds since the Epoch, and the tv_usec field, which represents the number of microseconds within the current second. The two values are then combined to produce a string with the format seconds.milliseconds.
 /// </summary>
function TimevalToString(tv: timeval): string;

/// <summary>
///   Returns a human-readable string representation of the specified size
/// </summary>
/// <param name="aSize">The size to convert</param>
/// <returns>A string representation of the specified size</returns>
function SizeToStr(aSize: int64) : String;

/// <summary>
/// Takes a pointer to a byte array and its size, and returns an array of strings, 
/// each containing a line of hexadecimal representation of the data with the ASCII representation
/// of the same data line, if printable. Non-printable characters are represented by a dot '.'.
/// </summary>
/// <param name="aPByteData">Pointer to a byte array containing data to be displayed in hexadecimal format</param>
/// <param name="aDataSize">Size of the data to be displayed in bytes</param>
/// <returns>An array of strings containing the hexadecimal representation of the data</returns>
function DisplayHexData(aPByteData: PByte; aDataSize: Integer;addInfo:Boolean=True): TArray<String>;
procedure MyProcessMessages;
function MyProcessMessage(var Msg: TMsg): Boolean;
function HexStrToBytes(const AHexStr: string): TBytes;

implementation

procedure MyProcessMessages;
var
  Msg: TMsg;
begin
  while MyProcessMessage(Msg) do {loop};
end;

function MyProcessMessage(var Msg: TMsg): Boolean;
var
  Unicode: Boolean;
  MsgExists: Boolean;
begin
  Result := False;
  if PeekMessage(Msg, 0, 0, 0, PM_NOREMOVE) then
  begin
{$IFDEF UNICODE}
    Unicode := (Msg.hwnd = 0) or IsWindowUnicode(Msg.hwnd);
{$ELSE}
    Unicode := (Msg.hwnd <> 0) and IsWindowUnicode(Msg.hwnd);
{$ENDIF}
    if Unicode then
      MsgExists := PeekMessageW(Msg, 0, 0, 0, PM_REMOVE)
    else
      MsgExists := PeekMessageA(Msg, 0, 0, 0, PM_REMOVE);

    if MsgExists then
    begin
      Result := True;
      if Msg.Message <> {WM_QUIT}$0012 then
      begin
        TranslateMessage(Msg);
        if Unicode then
          DispatchMessageW(Msg)
        else
          DispatchMessageA(Msg);
      end;
    end;
  end;
end;


function DisplayHexData(aPByteData: PByte; aDataSize: Integer;addInfo:Boolean=True): TArray<String>;
const HEXCHARS: array[0..15] of Char = '0123456789ABCDEF';
      LENGHT_ROW = 48;
var I           : Integer;
    J           : Integer;
    çRowCount   : Integer;
    LColumnCount: Integer;
    LText       : String;
    LLastLenght : Integer;
begin
  // Calculate the number of rows and columns needed to display the hexadecimal data
  çRowCount := (aDataSize + 15) div 16;
  LColumnCount := 16;

  // Initialize the array that will hold the hexadecimal data
  SetLength(Result, çRowCount);

  // Convert each byte in the data to its hexadecimal representation
  LText := String.Empty;
  for I := 0 to çRowCount - 1 do
  begin
    if not LText.IsEmpty and addInfo then
      Result[I-1] := Format('%s  %s',[Result[I-1],LText]);
    Result[I] := '';
    LText     := '';

    for J := 0 to LColumnCount - 1 do
    begin
      if I * LColumnCount + J < aDataSize then
      begin
        Result[I] := Format('%s %s%s',[Result[I],
                                        HEXCHARS[aPByteData[I * LColumnCount + J] shr 4] ,
                                        HEXCHARS[aPByteData[I * LColumnCount + J] and $0F]]);
        {The clear text part -  if it's displayable the do it}
        if (aPByteData[I * LColumnCount + J]>=32) and 
           (aPByteData[I * LColumnCount + J]<=127) 
        then
          LText := LText + char(aPByteData[I * LColumnCount + J])
        else
          LText := LText + '.'; {otherwise display a block char}                                     
      end
      else
        Result[I] := Result[I] + '  ';
      if J = 7 then
        Result[I] := Result[I] + ' ';
    end;
  end;
  if not LText.IsEmpty and addInfo then
  begin
    LLastLenght := Length(Result[çRowCount - 1]);
    for I := LLastLenght to LENGHT_ROW do
      Result[çRowCount - 1] := Format('%s ',[Result[çRowCount - 1]]);    
        
    Result[çRowCount - 1] := Format('%s  %s',[Result[çRowCount - 1],LText]);      
  end;  
end;

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

function BytesToIpV4(const aIp: TBytes): string;
var i: Integer;
begin
  Result := String.Empty;
  for i := Low(aIp) to High(aIp) do
  begin
    if Result.IsEmpty then
      Result := Format('%d',[aIp[i]])
    else
      Result := Format('%s.%d', [Result,aIp[i]])
  end;
end;


function IntToIPV4(ip: LongWord): string;
begin
  Result := IntToStr(ip and $FF) + '.' +
            IntToStr((ip shr 8) and $FF) + '.' +
            IntToStr((ip shr 16) and $FF) + '.' +
            IntToStr((ip shr 24) and $FF); 
end;


function MACAddressToString(const AMacAddress: TBytes): string;
var i: Integer;
begin
  Result := String.Empty;
  for i := Low(AMacAddress) to High(AMacAddress) do
  begin
    if not Result.IsEmpty then
       Result := Format('%s:',[Result]);
     Result := Format('%s%.2X', [Result,AMacAddress[i]])
  end;
end;

function HexStrToBytes(const AHexStr: string): TBytes;
var i       : Integer;
    hexValue: Byte;
begin
  SetLength(Result, Length(AHexStr) div 2);
  for i := 1 to Length(AHexStr) div 2 do
  begin
    hexValue      := StrToInt('$' + Copy(AHexStr, 2 * i - 1, 2));
    Result[i - 1] := hexValue;
  end;
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
    Result := Format('%d bytes', [aSize])
  else if aSize < MegaByte then
    Result := Format('%.2f KB', [aSize / KiloByte])
  else if aSize < GigaByte then
    Result := Format('%.2f MB', [aSize / MegaByte])
  else 
    Result := Format('%.2f GB', [aSize / GigaByte])
end;



end.
