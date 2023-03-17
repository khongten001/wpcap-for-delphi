unit wpcap.Protocol.FTP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,
  Wpcap.protocol.TCP,System.Variants,Wpcap.BufferUtils,wpcap.StrUtils;

type
  {https://datatracker.ietf.org/doc/html/rfc959}


  TFTPHeader = packed record
    OpCode   : Byte;  // The opcode specifying the type of FTP message
    Data     : word;  // Data field for the FTP message
    Sequence : word;  // Sequence number of the message
  end;
  
  /// <summary>
  /// The FTP protocol implementation class.
  /// </summary>
  TWPcapProtocolFTP = Class(TWPcapProtocolBaseTCP)
  private
    const
      FTP_OP_DATA   = 0;     // Data packet                                                    
      FTP_OP_EOF    = 1;     // End of file
      FTP_OP_DIR    = 2;     // Directory listing
      FTP_OP_ERR    = 3;     // Error message
      FTP_OP_ACK    = 4;     // Acknowledgment
      FTP_OP_NAK    = 5;     // Negative acknowledgment
      FTP_OP_RESEND = 6;     // Resend packet
      FTP_OP_ABORT  = 7;     // Abort transfer  
  protected
  public
    /// <summary>
    /// Returns the default FTP port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the FTP protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the FTP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the POP3 protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function HeaderToString(const aPacketData: PByte; aPacketSize: Integer; AListDetail: TListHeaderString): Boolean; override;    
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolPOP3 }
class function TWPcapProtocolFTP.DefaultPort: Word;
begin
  Result := PROTO_FTP_PORT;
end;

class function TWPcapProtocolFTP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_FTP
end;

class function TWPcapProtocolFTP.ProtoName: String;
begin
  Result := 'File transfer protocol';
end;

class function TWPcapProtocolFTP.AcronymName: String;
begin
  Result := 'FTP';
end;

class function TWPcapProtocolFTP.HeaderToString(const aPacketData: PByte;aPacketSize: Integer; AListDetail: TListHeaderString): Boolean;
var LTCPPayLoad : PByte;
    LTCPPHdr    : PTCPHdr;
begin
  Result := False;

  if not HeaderTCP(aPacketData,aPacketSize,LTCPPHdr) then Exit;

  LTCPPayLoad := GetTCPPayLoad(aPacketData,aPacketSize);

  AListDetail.Add(AddHeaderInfo(0, Format('%s (%s)', [ProtoName, AcronymName]), null, nil,0));

  Result := True;
end;

end.
                                                 
