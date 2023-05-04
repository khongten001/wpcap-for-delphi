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

unit wpcap.Protocol.TFTP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,wpcap.StrUtils,wpcap.packet,
  Wpcap.protocol.UDP, WinApi.Windows,wpcap.BufferUtils,Variants,idGlobal;
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
    OpCode    : Uint16;
    FileName  : array[0..MAX_PATH] of AnsiChar;
  end;
  PTTFTPHeaderRRQ_WRQ = ^TTFTPHeaderRRQ_WRQ;

  TTFTPHeaderData = packed record
    OpCode     : Uint16;
    BlockNumber: Uint16;
    Data       : array[0..TFTP_DATA_SIZE-1] of Uint8;
  end;
  PTTFTPHeaderData = ^TTFTPHeaderData;
  
  TTFTPHeaderAck = packed record
    OpCode     : Uint16;
    BlockNumber: Uint16;
  end;
  PTTFTPHeaderAck = ^TTFTPHeaderAck;
  
  TTFTPHeaderError = packed record
    OpCode      : Uint16;
    ErrorCode   : Uint16;
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
    class function OpcodeToString(opcode: Uint16): string; static;
    class function ErrorCodeToString(ErrorCode: Uint16): string; static;
  protected
  public
    /// <summary>
    /// Returns the default TFTP port (110).
    /// </summary>
    class function DefaultPort: word; override;
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
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalInfo: PTAdditionalInfo): Boolean; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Uint8): Boolean; override;        
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolTFTP }

class function TWPcapProtocolTFTP.OpcodeToString(opcode: Uint16): string;
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
end;

class function TWPcapProtocolTFTP.ErrorCodeToString(ErrorCode: Uint16): string;
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
end;


class function TWPcapProtocolTFTP.DefaultPort: word;
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
  aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Uint8): Boolean;
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

class function TWPcapProtocolTFTP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalInfo: PTAdditionalInfo): Boolean;
var LUDPPayLoad        : PByte;
    LDummy             : Integer;
    LOpCode            : Uint16;
    LTFTPHeaderRRQ_WRQ : PTTFTPHeaderRRQ_WRQ;
    LTFTPHeaderData    : PTTFTPHeaderData;
    LTFTPHeaderAck     : PTTFTPHeaderAck;
    LTFTPHeaderError   : PTTFTPHeaderError;
    LType              : array[0..MAX_PATH] of AnsiChar;
    LFileLen           : Uint32;
    LDataArray         : TArray<Uint8>;
    LUdpPayLoadLen     : integer;
begin
  Result         := False;
  LUDPPayLoad    := inherited GetPayLoad(aPacketData,aPacketSize,LUdpPayLoadLen,LDummy); 
  LOpCode        := wpcapntohs(PUint16(LUDPPayLoad)^);    
  FIsFilterMode  := aIsFilterMode;
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, LUDPPayLoad,LUdpPayLoadLen));
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.OpCode',[AcronymName]), 'OpCode:',OpcodeToString(LOpCode) , @LOpCode, SizeOf(LOpCode), LOpCode ));

  case LOpCode of
    TFTP_RRQ, 
    TFTP_WRQ  :
      begin
        LTFTPHeaderRRQ_WRQ := PTTFTPHeaderRRQ_WRQ(LUDPPayLoad);  
        LFileLen           :=  StrLen(( LTFTPHeaderRRQ_WRQ.Filename));    
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SourceName',[AcronymName]), 'Source name:', StrPas(LTFTPHeaderRRQ_WRQ.Filename), @LTFTPHeaderRRQ_WRQ.Filename,LFileLen));

        Move(LUDPPayLoad[SizeOf(LOpCode)+LFileLen+1],LType,SizeOf(LType));
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Type',[AcronymName]), 'Type:', StrPas(LType), @LType, StrLen(LType)));        
      end;
    TFTP_DATA : 
      begin
        LTFTPHeaderData := PTTFTPHeaderData(LUDPPayLoad);   
         
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.BlockNumber',[AcronymName]), 'BlockNumber:',wpcapntohs(LTFTPHeaderData.BlockNumber) , @LTFTPHeaderData.BlockNumber, SizeOf(LTFTPHeaderData.BlockNumber)));     
        
        SetLength(LDataArray,LUdpPayLoadLen - SizeOf(LTFTPHeaderData.BlockNumber));
        Move(LTFTPHeaderData.Data, LDataArray[0],LUdpPayLoadLen - SizeOf(LTFTPHeaderData.BlockNumber));           
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Data',[AcronymName]), 'Data:', SizeToStr(LUdpPayLoadLen - SizeOf(LTFTPHeaderData.BlockNumber)), @LDataArray,LUdpPayLoadLen - SizeOf(LTFTPHeaderData.BlockNumber)));
              
      end;
    TFTP_ACK  :
      begin
        LTFTPHeaderAck := PTTFTPHeaderAck(LUDPPayLoad);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.BlockNumber',[AcronymName]), 'BlockNumber:',wpcapntohs(LTFTPHeaderAck.BlockNumber) , @LTFTPHeaderAck.BlockNumber, SizeOf(LTFTPHeaderAck.BlockNumber)));        
      end;
    TFTP_ERROR :
      begin
        LTFTPHeaderError := PTTFTPHeaderError(LUDPPayLoad);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.ErrorCode',[AcronymName]), 'ErrorCode:',ErrorCodeToString(wpcapntohs(LTFTPHeaderError.ErrorCode)) , @LTFTPHeaderError.ErrorCode, SizeOf(LTFTPHeaderError.ErrorCode), wpcapntohs(LTFTPHeaderError.ErrorCode) ));                      
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.ErrorMessage',[AcronymName]), 'ErrorMessage:', StrPas(LTFTPHeaderError.ErrorMessage), @LTFTPHeaderError.ErrorMessage, StrLen(LTFTPHeaderError.ErrorMessage)));
      End
  end;

  Result := True;
end;


end.
                                                 
