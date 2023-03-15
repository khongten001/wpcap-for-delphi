unit wpcap.Protocol.FTP;

interface

uses wpcap.Protocol.Base,wpcap.Conts,wpcap.Types,System.SysUtils,Wpcap.protocol.TCP;

type

  /// <summary>
  /// The FTP protocol implementation class.
  /// </summary>
  TWPcapProtocolFTP = Class(TWPcapProtocolBaseTCP)
  private
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


end.
                                                 
