unit wpcap.BufferUtils;

interface
uses System.SysUtils,winsock2;

/// <summary>
/// Converts an array of bytes to a TBytes dynamic array.
/// </summary>
/// <param name="Bytes">The input byte array.</param>
/// <returns>Returns a TBytes dynamic array containing the same bytes as the input array.</returns>
function BytesToArray(const Bytes: array of Byte): TBytes;

/// <summary>
/// Converts a 16-bit integer from network byte order to host byte order.
/// </summary>
/// <param name="aWord">The input 16-bit integer in network byte order.</param>
/// <returns>Returns the input 16-bit integer in host byte order.</returns>
function wpcapntohs(aWord: Word): word;

/// <summary>
/// Extracts the byte at the specified index from a 16-bit integer value.
/// </summary>
/// <param name="aWordValue">The input 16-bit integer value.</param>
/// <param name="aByteIndex">The index of the byte to extract (0 or 1).</param>
/// <returns>Returns the byte at the specified index of the input 16-bit integer value.</returns>
function GetByteFromWord(aWordValue: Word; aByteIndex: Integer): Byte;

/// <summary>
/// Gets the value of a single bit at the specified index of a byte value.
/// </summary>
/// <param name="AByteValue">The input byte value.</param>
/// <param name="AIndexBit">The index of the bit to retrieve (0-7).</param>
/// <returns>Returns the value of the specified bit (0 or 1) from the input byte value.</returns>
function GetBitValue(const AByteValue: Byte; const AIndexBit: Byte): Byte;

/// <summary>
/// Converts a byte value to a binary string representation.
/// </summary>
/// <param name="AByte">The input byte value.</param>
/// <returns>Returns a string containing the binary representation of the input byte value.</returns>
function ByteToBinaryString(const AByte: Byte): string;

/// <summary>
/// Converts an integer value to a binary string representation with the specified number of digits.
/// </summary>
/// <param name="Value">The input integer value.</param>
/// <param name="Digits">The number of digits in the binary string representation.</param>
/// <returns>Returns a string containing the binary representation of the input integer value with the specified number of digits.</returns>
function IntToBin(Value: integer; Digits: integer): string;


implementation


function BytesToArray(const Bytes: array of Byte): TBytes;
var I: Integer;
begin
  SetLength(Result, Length(Bytes));
  for I := Low(Bytes) to High(Bytes) do
    Result[I] := Bytes[I];
end;

function wpcapntohs(aWord: Word):word;
begin
  {Swap or ntohs difference ?}
  result := ntohs(aWord);
end;

function GetByteFromWord(aWordValue: Word; aByteIndex: Integer): Byte;
begin
  if (aByteIndex < 0) and (aByteIndex > 1) then
   raise Exception.CreateFmt('GetByteFromWord out of range [%d]',[aByteIndex]);

  Result := (aWordValue shr (aByteIndex * 8)) and $FF
end;


Function GetBitValue(const AByteValue: Byte; const AIndexBit: Byte): Byte;
begin
  if (aIndexBit < 1) or (aIndexBit > 8) then
    raise Exception.CreateFmt('GetBitValue out of range [%d]',[aIndexBit]);

  result := (AByteValue shr (8 - AIndexBit) ) and $01;     
end;

function IntToBin(Value: integer; Digits: integer): string;
var
  i: integer;
begin
  Result := '';
  for i := Digits-1 downto 0 do
    if (Value and (1 shl i)) <> 0 then
      Result := Result + '1'
    else
      Result := Result + '0';
end;

function ByteToBinaryString(const AByte: Byte): string;
begin
  Result := IntToBin(AByte, 8);
end;


end.
