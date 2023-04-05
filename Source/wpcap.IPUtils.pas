﻿unit wpcap.IPUtils;

interface

uses WinApi.Windows,System.Classes,System.SysUtils,IdGlobal,System.Math,IdGlobalProtocols;

/// <summary>
/// This function takes a byte array representing the IPv6 address in the TIPv6Header structure, and returns
/// a string representing the address in standard format separated by colons. The function also deletes sections of
/// consecutive zeros so as to make the address more compact.
/// </summary>
function IPv6AddressToString(const Address: array of Byte): string;

function IPv6ToUInt64(const AIPAddress: string): UInt64;

Function IsValidPublicIP(Const aIP : String):Boolean;

implementation


function IPv6ToUInt64(const AIPAddress: string): UInt64;
var LAddress: TidIPv6Address;
    I       : Integer;
begin
  IPv6ToIdIPv6Address(AIPAddress,LAddress);

  Result := 0;
  for I := Low(LAddress) to High(LAddress) do
  begin
    Result := Result shl 16;
    Result := Result or Swap(LAddress[I]);
  end;
end;


Function IsValidPublicIP(Const aIP : String):Boolean;
var IP4     : Cardinal;
    FR4     : Cardinal;
    TO4     : Cardinal;
    Provider: Boolean;   
    iIP     : Int64;
begin
  Result   := True;
  Provider := False;
  Try
    if isValidIP(aIP) then
    begin
      if TryStrToInt64(StringReplace(Trim(aIP),'.','',[rfReplaceAll]),iIP) then
      begin
        IP4     := IPv4ToUint32(aIP);
        FR4     := IPv4ToUint32('10.0.0.0');
        TO4     := IPv4ToUint32('10.255.255.255');
        Result  := Not InRange(IP4, FR4, TO4);
        if Result then
        begin
          FR4     := IPv4ToUint32('172.16.0.0');
          TO4     := IPv4ToUint32('172.31.255.255');
          Result  := Not InRange(IP4, FR4, TO4);
          if Result then
          begin
            FR4     := IPv4ToUint32('192.168.0.0');
            TO4     := IPv4ToUint32('192.168.255.255');
            Result  := Not InRange(IP4, FR4, TO4);

            if Result then
            begin
              Provider:= True;
              FR4     := IPv4ToUint32('100.64.0.0');
              TO4     := IPv4ToUint32('100.127.255.255');
              Result  := Not InRange(IP4, FR4, TO4);
            end;
          end;
        end
      end
      else result := aIP.Trim.StartsWith('FC',true) or  aIP.Trim.StartsWith('FD',True);       
    end;
  Except
    Result := False;
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




end.
