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

unit wpcap.Protocol.FTP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,
  Wpcap.protocol.TCP,System.Variants,Wpcap.BufferUtils,wpcap.StrUtils;

type
  {https://datatracker.ietf.org/doc/html/rfc959}


  TFTPHeader = packed record
    OpCode   : Uint8;  // The opcode specifying the type of FTP message
    Data     : Uint16;  // Data field for the FTP message
    Sequence : Uint16;  // Sequence number of the message
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
      FTP_OP_ABORT  = 7;
    class function ResponseToString(const aResponse: Uint16): String; static;     // Abort transfer  
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
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean; override;    
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

class function TWPcapProtocolFTP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LTCPPayLoad    : PByte;
    LTCPPayLoadLen : Integer;
    LTCPPHdr       : PTCPHdr;
    LOffSet        : Integer;
begin
  Result := False;

  if not HeaderTCP(aPacketData,aPacketSize,LTCPPHdr) then Exit;

  LTCPPayLoad     := GetTCPPayLoad(aPacketData,aPacketSize);
  FIsFilterMode   := aIsFilterMode;
  LTCPPayLoadLen  := TCPPayLoadLength(LTCPPHdr,aPacketData,aPacketSize);
  AListDetail.Add(AddHeaderInfo(aStartLevel, AcronymName , Format('%s (%s)', [ProtoName, AcronymName]), null, LTCPPayLoad,LTCPPayLoadLen));
  LOffSet    := 0;  
  Result     := ParserByEndOfLine(aStartLevel,LTCPPayLoadLen,LTCPPayLoad,AListDetail,LOffSet);
end;

class function TWPcapProtocolFTP.ResponseToString(const aResponse:Uint16):String;
begin
  case aResponse of
     110: Result:= 'Restart marker reply';
     120: Result:= 'Service ready in nnn minutes';
     125: Result:= 'Data connection already open; transfer starting';
     150: Result:= 'File status okay; about to open data connection';
     200: Result:= 'Command okay';
     202: Result:= 'Command not implemented, superfluous at this site';
     211: Result:= 'System status, or system help reply';
     212: Result:= 'Directory status';
     213: Result:= 'File status';
     214: Result:= 'Help message';
     215: Result:= 'NAME system type';
     220: Result:= 'Service ready for new user';
     221: Result:= 'Service closing control connection';
     225: Result:= 'Data connection open; no transfer in progress';
     226: Result:= 'Closing data connection';
     227: Result:= 'Entering Passive Mode';
     229: Result:= 'Entering Extended Passive Mode';
     230: Result:= 'User logged in, proceed';
     232: Result:= 'User logged in, authorized by security data exchange';
     234: Result:= 'Security data exchange complete';
     235: Result:= 'Security data exchange completed successfully';
     250: Result:= 'Requested file action okay, completed';
     257: Result:= 'PATHNAME created';
     331: Result:= 'User name okay, need password';
     332: Result:= 'Need account for login';
     334: Result:= 'Requested security mechanism is ok';
     335: Result:= 'Security data is acceptable, more is required';
     336: Result:= 'Username okay, need password. Challenge is ...';
     350: Result:= 'Requested file action pending further information';
     421: Result:= 'Service not available, closing control connection';
     425: Result:= 'Can''t open data connection';
     426: Result:= 'Connection closed; transfer aborted';
     431: Result:= 'Need some unavailable resource to process security';
     450: Result:= 'Requested file action not taken';
     451: Result:= 'Requested action aborted: local error in processing';
     452: Result:= 'Requested action not taken. Insufficient storage space in system';
     500: Result:= 'Syntax error, command unrecognized';
     501: Result:= 'Syntax error in parameters or arguments';
     502: Result:= 'Command not implemented';
     503: Result:= 'Bad sequence of commands';
     504: Result:= 'Command not implemented for that parameter';
     522: Result:= 'Network protocol not supported';
     530: Result:= 'Not logged in';
     532: Result:= 'Need account for storing files';
     533: Result:= 'Command protection level denied for policy reasons';
     534: Result:= 'Request denied for policy reasons';
     535: Result:= 'Failed security check (hash, sequence, etc)';
     536: Result:= 'Requested PROT level not supported by mechanism';
     537: Result:= 'Command protection level not supported by security mechanism';
     550: Result:= 'Requested action not taken: File unavailable';
     551: Result:= 'Requested action aborted: page type unknown';
     552: Result:= 'Requested file action aborted: Exceeded storage allocation';
     553: Result:= 'Requested action not taken: File name not allowed';
     631: Result:= 'Integrity protected reply';
     632: Result:= 'Confidentiality and integrity protected reply';
     633: Result:= 'Confidentiality protected reply';
  else
    Result := 'Unknown'  
  end;
end;
 

end.
                                                 
