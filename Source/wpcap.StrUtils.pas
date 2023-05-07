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

unit wpcap.StrUtils;

interface

uses
  WinApi.Windows, WinSock, System.SysUtils, DateUtils, System.Classes, idGlobal,
  wpcap.Types, System.Variants;

/// <summary>
/// The function MACAddrToStr takes an array of bytes representing a MAC address and converts it into a string representation in the format of "XX:XX:XX:XX:XX:XX",
/// where each "XX" represents a two-digit hexadecimal number corresponding to each byte in the array. The resulting string is returned by the function.
/// </summary>
function MACAddrToStr(const MACAddr: array of Byte): string;

function MACAddressToString(const AMacAddress: TIdBytes): string;

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


function BufferToASCII(aPByteData: PByte; aDataSize: Integer):AnsiString;
function LongWordToString(const aValue: LongWord): string;
function HeaderStringListToXML(const aHeaderStrings: TListHeaderString;out aListLabel:TListLabelByLevel): string;

implementation


function HeaderStringListToXML(const aHeaderStrings: TListHeaderString; out aListLabel: TListLabelByLevel): string;
var
  I               : Integer;
  LStringBuilder  : TStringBuilder;
  LLevel          : Integer;
  LLabelName      : string;
  LDescription    : string;
  LValue          : string;
  LRawValue       : string;
  LLabelByLevelID : String;
  LLabelByLevel   : TLabelByLevel; 
begin
  if not Assigned(aListLabel) then
    raise Exception.Create('List of label for database filter not assigned');

  LStringBuilder := TStringBuilder.Create;
  try
    LStringBuilder.Append('<HeaderStrings>');
    I := 0;
    while I < aHeaderStrings.Count - 1 do
    begin
      LLevel       := aHeaderStrings[I].Level;
      LLabelName   := aHeaderStrings[I].Labelname.Trim;
      LDescription := aHeaderStrings[I].Description.Trim;
      LValue       := VarToStrDef(aHeaderStrings[I].Value,'');
      LRawValue    := VarToStrDef(aHeaderStrings[I].RawValue,'');
      Inc(I);
      if not LLabelName.Trim.IsEmpty then
      begin
        LStringBuilder.Append(Format('<Item Level="%d" LabelName="%s" Description="%s" Value="%s" RawValue="%s">', 
          [LLevel, LLabelName, LDescription, LValue, LRawValue]));


        LLabelByLevelID           := Format('%s_%d',[LLabelName,LLevel]);
        LLabelByLevel.Level       := LLevel;
        LLabelByLevel.LabelName   := LLabelName.Trim;
        LLabelByLevel.Description := LDescription.Trim;
        aListLabel.TryAdd(LLabelByLevelID,LLabelByLevel);          
        
        while I < aHeaderStrings.Count - 1 do
        begin
          if aHeaderStrings[I].Level = 0 then
            Break;

          if aHeaderStrings[I].Level <= LLevel then
            Break;

          LLevel       := aHeaderStrings[I].Level;
          LLabelName   := aHeaderStrings[I].Labelname;
          LDescription := aHeaderStrings[I].Description;
          LValue       := VarToStrDef(aHeaderStrings[I].Value,'');
          LRawValue    := VarToStrDef(aHeaderStrings[I].RawValue,'');

          LStringBuilder.Append(Format('<Item Level="%d" LabelName="%s" Description="%s" Value="%s" RawValue="%s">', 
            [LLevel, LLabelName, LDescription, LValue, LRawValue]));

          LLabelByLevelID           := Format('%s_%d',[LLabelName,LLevel]);
          LLabelByLevel.Level       := LLevel;
          LLabelByLevel.LabelName   := LLabelName;
          LLabelByLevel.Description := LDescription;
          aListLabel.TryAdd(LLabelByLevelID,LLabelByLevel);   
          Inc(I);
        end;

        LStringBuilder.Append('</Item>');
      end;
    end;

    LStringBuilder.Append('</HeaderStrings>');
    Result := LStringBuilder.ToString;
  finally
    LStringBuilder.Free;
  end;
end;


function LongWordToString(const aValue: LongWord): string;
var LBytes: TidBytes;
begin
  SetLength(LBytes, SizeOf(aValue));
  Move(aValue, LBytes[0], SizeOf(aValue)); // Copy the LongWord value to a byte array
  Result := BytesToStringRaw(LBytes); // Convert the byte array to a string
end;

function DisplayHexData(aPByteData: PByte; aDataSize: Integer; addInfo: Boolean = True): TArray<String>;
const
  HEXCHARS: array[0..15] of Char = '0123456789ABCDEF';
  LENGTH_ROW = 48;
var
  I, J       : Integer;
  RowCount   : Integer;
  ColumnCount: Integer;
  LastLength : Integer;
  Buffer     : TStringBuilder;
  LText      : String;
begin
  // Calculate the number of rows and columns needed to display the hexadecimal data
  RowCount    := (aDataSize + 15) div 16;
  ColumnCount := 16;

  // Initialize the array that will hold the hexadecimal data
  SetLength(Result, RowCount);

  // Convert each byte in the data to its hexadecimal representation
  Buffer := TStringBuilder.Create;
  Try
    for I := 0 to RowCount - 1 do
    begin
      if not (Buffer.Length = 0) and addInfo then
      begin
        Result[I-1] := Buffer.ToString;
        Buffer.Clear;
      end;
      Result[I] := '';
      LText     := '';

      for J := 0 to ColumnCount - 1 do
      begin
        if I * ColumnCount + J < aDataSize then
        begin
          Result[I] := Format('%s %s%s', [Result[I] ,HEXCHARS[aPByteData[I * ColumnCount + J] shr 4], HEXCHARS[aPByteData[I * ColumnCount + J] and $0F]]);
               
          {The clear text part -  if it's displayable the do it}
          if (aPByteData[I * ColumnCount + J] >= 32) and
            (aPByteData[I * ColumnCount + J] <= 127) 
          then
            LText := LText + char(aPByteData[I * ColumnCount + J])
          else
            LText := LText + '.'; {otherwise display a block char}
        end
        else
          Result[I] := Result[I] + '  ';

        if J = 7 then
          Result[I] := Result[I] + ' ';
      end;

      if not LText.IsEmpty then
      begin
        if addInfo then
          Buffer.AppendFormat('%s  %s', [Result[I], LText])
        else
          Buffer.Append(LText);
      end;
    end;

    if not (Buffer.Length=0) and addInfo then
    begin
      LastLength := Length(Result[RowCount - 1]);
    
      for I := LastLength to LENGTH_ROW do
        Result[RowCount - 1] := Format('%s ', [Result[RowCount - 1]]);
      Result[RowCount - 1] := Buffer.ToString;
    end;
  Finally
    FreeAndNil(Buffer);
  End;
end;


function BufferToASCII(aPByteData: PByte; aDataSize: Integer):AnsiString;
var J : Integer;
begin

  SetLength(Result,aDataSize);
  FillChar(Result[1],aDataSize,AnsiChar(46));
  for J := 0 to aDataSize -1 do
  begin    
    if ( (aPByteData[J]>=32) and 
       (aPByteData[J]<=127) ) or (aPByteData[J]=10) or (aPByteData[J]=13)
    then
      Result[J+1] := AnsiChar(aPByteData[J]) 
  end;
end;

function MACAddressToString(const AMacAddress: TIdBytes): string;
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
