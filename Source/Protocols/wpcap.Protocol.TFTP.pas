unit wpcap.Protocol.TFTP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,wpcap.StrUtils,
  Wpcap.protocol.UDP, WinApi.Windows,wpcap.BufferUtils,Variants;
CONST
  TFTP_DATA_SIZE = 512;
type
   {https://tools.ietf.org/html/rfc1350.}
  {
          2 bytes    string   1 byte     string   1 byte
          -----------------------------------------------
   RRQ/  | 01/02 |  Filename  |   0  |    Mode    |   0  |
   WRQ    -----------------------------------------------
   
          2 bytes    2 bytes       n bytes
          ---------------------------------
   DATA  | 03    |   Block #  |    Data    |
          ---------------------------------
          2 bytes    2 bytes
          -------------------
   ACK   | 04    |   Block #  |
          --------------------
          2 bytes  2 bytes        string    1 byte
          ----------------------------------------
   ERROR | 05    |  ErrorCode |   ErrMsg   |   0  |
  }


  TTFTPHeaderRRQ_WRQ = packed record
    OpCode    : Word;
    FileName  : array[0..MAX_PATH] of AnsiChar;
  end;
  PTTFTPHeaderRRQ_WRQ = ^TTFTPHeaderRRQ_WRQ;

  TTFTPHeaderData = packed record
    OpCode     : Word;
    BlockNumber: Word;
    Data       : array[0..TFTP_DATA_SIZE-1] of Byte;
  end;
  PTTFTPHeaderData = ^TTFTPHeaderData;
  
  TTFTPHeaderAck = packed record
    OpCode     : Word;
    BlockNumber: Word;
  end;
  PTTFTPHeaderAck = ^TTFTPHeaderAck;
  
  TTFTPHeaderError = packed record
    OpCode      : Word;
    ErrorCode   : Word;
    ErrorMessage: array[0..MAX_PATH] of AnsiChar;
  end;
  PTTFTPHeaderError = ^TTFTPHeaderError;
  
  /// <summary>
  /// The TFTP protocol implementation class.
  /// </summary>
  TWPcapProtocolTFTP = Class(TWPcapProtocolBaseUDP)
  private
    CONST
    TFTP_RRQ   = 1;  // Read request
    TFTP_WRQ   = 2;  // Write request
    TFTP_DATA  = 3;  // Data
    TFTP_ACK   = 4;  // Acknowledgment
    TFTP_ERROR = 5;    
    class function OpcodeToString(opcode: Word): string; static;
    class function ErrorCodeToString(ErrorCode: Word): string; static;
  protected
  public
    /// <summary>
    /// Returns the default TFTP port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the TFTP protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the TFTP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the POP3 protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString): Boolean; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; override;        
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolTFTP }

class function TWPcapProtocolTFTP.OpcodeToString(opcode: Word): string;
begin
  case opcode of
    TFTP_RRQ  : Result   := 'Read request';
    TFTP_WRQ  : Result   := 'Write request';
    TFTP_DATA : Result   := 'Data';
    TFTP_ACK  : Result   := 'Acknowledgment';
    TFTP_ERROR: Result   := 'Error';
  else 
      Result := 'Unknown opcode';
  end;

  Result := Format('%s [%d]',[Result,opCode]);
end;

class function TWPcapProtocolTFTP.ErrorCodeToString(ErrorCode: Word): string;
begin
  case ErrorCode of
    0: Result := 'Not defined, see error message (if any)';
    1: Result := 'File not found';
    2: Result := 'Access violation';
    3: Result := 'Disk full or allocation exceeded';
    4: Result := 'Illegal TFTP operation';
    5: Result := 'Unknown transfer ID';
    6: Result := 'File already exists';
    7: Result := 'No such user';
    8: Result := 'Terminate transfer due to option negotiation failure';
    else Result := 'Unknown error code';
  end;

    Result := Format('%s [%d]',[Result,ErrorCode]);
end;


class function TWPcapProtocolTFTP.DefaultPort: Word;
begin
  Result := PROTO_TFTP_PORT;
end;

class function TWPcapProtocolTFTP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_TFTP
end;

class function TWPcapProtocolTFTP.ProtoName: String;
begin
  Result := 'Trivial File Transfer Protocol';
end;

class function TWPcapProtocolTFTP.IsValid(const aPacket: PByte;
  aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LUDPPPtr: PUDPHdr;
begin
  Result  := inherited IsValid(aPacket,aPacketSize,aAcronymName,aIdProtoDetected);  
  if not Result then
  begin
    if not HeaderUDP(aPacket,aPacketSize,LUDPPPtr) then exit;   
    if not PayLoadLengthIsValid(LUDPPPtr) then  Exit;
    Result := IsValidByPort(50618,DstPort(LUDPPPtr),SrcPort(LUDPPPtr),aAcronymName,aIdProtoDetected)  
  end;
end;

class function TWPcapProtocolTFTP.AcronymName: String;
begin
  Result := 'TFTP';
end;

class function TWPcapProtocolTFTP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString): Boolean;
var LUDPPayLoad        : PByte;
    LPUDPHdr           : PUDPHdr;
    LOpCode            : Word;
    LTFTPHeaderRRQ_WRQ : PTTFTPHeaderRRQ_WRQ;
    LTFTPHeaderData    : PTTFTPHeaderData;
    LTFTPHeaderAck     : PTTFTPHeaderAck;
    LTFTPHeaderError   : PTTFTPHeaderError;
    LType              : array[0..MAX_PATH] of AnsiChar;
    LFileLen           : Cardinal;
    LDataArray         : TArray<Byte>;
    LUdpPayLoadLen     : integer;
begin
  Result := False;

  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad := GetUDPPayLoad(aPacketData,aPacketSize);
  LOpCode     := wpcapntohs(PWord(LUDPPayLoad)^);    

  AListDetail.Add(AddHeaderInfo(aStartLevel, Format('%s (%s)', [ProtoName, AcronymName]), null, nil,0));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'OpCode:',OpcodeToString(LOpCode) , @LOpCode, SizeOf(LOpCode)));

  case LOpCode of
    TFTP_RRQ, 
    TFTP_WRQ  :
      begin
        LTFTPHeaderRRQ_WRQ := PTTFTPHeaderRRQ_WRQ(LUDPPayLoad);  
        LFileLen  :=  StrLen(LTFTPHeaderRRQ_WRQ.Filename);    
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'Source name:', StrPas(LTFTPHeaderRRQ_WRQ.Filename), @LTFTPHeaderRRQ_WRQ.Filename,LFileLen));

        Move(LUDPPayLoad[SizeOf(LOpCode)+LFileLen+1],LType,SizeOf(LType));
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'Type:', StrPas(LType), @LType, StrLen(LType)));        
      end;
    TFTP_DATA : 
      begin
        LTFTPHeaderData := PTTFTPHeaderData(LUDPPayLoad);   
         
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'BlockNumber:',wpcapntohs(LTFTPHeaderData.BlockNumber) , @LTFTPHeaderData.BlockNumber, SizeOf(LTFTPHeaderData.BlockNumber)));     
        LUdpPayLoadLen := UDPPayLoadLength(LPUDPHdr)-SizeOf(LOpCode)-8;
        SetLength(LDataArray,LUdpPayLoadLen - SizeOf(LTFTPHeaderData.BlockNumber));
        Move(LTFTPHeaderData.Data, LDataArray[0],LUdpPayLoadLen - SizeOf(LTFTPHeaderData.BlockNumber));           
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'Data:', SizeToStr(LUdpPayLoadLen - SizeOf(LTFTPHeaderData.BlockNumber)), @LDataArray,LUdpPayLoadLen - SizeOf(LTFTPHeaderData.BlockNumber)));
              
      end;
    TFTP_ACK  :
      begin
        LTFTPHeaderAck := PTTFTPHeaderAck(LUDPPayLoad);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'BlockNumber:',wpcapntohs(LTFTPHeaderAck.BlockNumber) , @LTFTPHeaderAck.BlockNumber, SizeOf(LTFTPHeaderAck.BlockNumber)));        
      end;
    TFTP_ERROR :
      begin
        LTFTPHeaderError := PTTFTPHeaderError(LUDPPayLoad);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'ErrorCode:',ErrorCodeToString(wpcapntohs(LTFTPHeaderError.ErrorCode)) , @LTFTPHeaderError.ErrorCode, SizeOf(LTFTPHeaderError.ErrorCode)));                      
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'ErrorMessage:', StrPas(LTFTPHeaderError.ErrorMessage), @LTFTPHeaderError.ErrorMessage, StrLen(LTFTPHeaderError.ErrorMessage)));
      End
  end;

  Result := True;
end;


end.
                                                 
