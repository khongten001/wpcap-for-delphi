unit wpcap.Protocol.POP3;

interface

uses wpcap.Protocol.Base,wpcap.Conts,wpcap.Types,System.SysUtils,Wpcap.protocol.TCP;

type

  /// <summary>
  /// The POP3 protocol implementation class.
  /// </summary>
  TWPcapProtocolPOP3 = Class(TWPcapProtocolBaseTCP)
  private
  protected
  public
    /// <summary>
    /// Returns the default POP3 port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the POP3 protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the POP3 protocol.
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
class function TWPcapProtocolPOP3.DefaultPort: Word;
begin
  Result := PROTO_POP3_PORT;
end;

class function TWPcapProtocolPOP3.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_POP3
end;

class function TWPcapProtocolPOP3.ProtoName: String;
begin
  Result := 'Post Office Protocol';
end;

class function TWPcapProtocolPOP3.AcronymName: String;
begin
  Result := 'POP3';
end;


end.
                                                 
