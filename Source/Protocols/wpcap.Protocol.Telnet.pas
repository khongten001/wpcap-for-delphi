unit wpcap.Protocol.Telnet;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,System.StrUtils,
  Wpcap.protocol.TCP,System.Variants,Wpcap.BufferUtils,wpcap.StrUtils,System.Math;

type

  {
  RFC 854: Telnet Protocol Specification - https://tools.ietf.org/html/rfc854
  RFC 855: Telnet Option Specifications - https://tools.ietf.org/html/rfc855
  RFC 1184: Telnet Linemode Option - https://tools.ietf.org/html/rfc1184
  RFC 1372: Telnet Remote Flow Control Option - https://tools.ietf.org/html/rfc1372
  }

  
  /// <summary>
  /// The Telnet protocol implementation class.
  /// </summary>
  TWPcapProtocolTelnet = Class(TWPcapProtocolBaseTCP)
  private
    CONST 
          TELNET_CMD_IAC           = 255;
          {ommand}
          TELNET_CMD_EW            = 22;
          TELNET_CMD_CBT           = 6;
          TELNET_CMD_SRS           = 65;
          TELNET_CMD_SDS           = 67;
          TELNET_CMD_SIM           = 69;
          TELNET_CMD_SAK           = 70;       
          TELNET_CMD_EOF           = 236;          
          TELNET_CMD_SUSP          = 237;
          TELNET_CMD_ABORT         = 238;   
          TELNET_CMD_EOR           = 239;
          TELNET_CMD_SE            = 240;
          TELNET_CMD_NOP           = 241;             
          TELNET_CMD_DM            = 242;
          TELNET_CMD_BRK           = 243;
          TELNET_CMD_IP            = 244;
          TELNET_CMD_AO            = 245;
          TELNET_CMD_AYT           = 246;
          TELNET_CMD_EC            = 247;
          TELNET_CMD_EL            = 248;
          TELNET_CMD_GA            = 249;
          TELNET_CMD_SB            = 250;
          TELNET_CMD_WILL          = 251;
          TELNET_CMD_WONT          = 252;
          TELNET_CMD_DO            = 253;  
          TELNET_CMD_DONT          = 254;                
          
          {Options}
          TELNET_OPT_BINARY        = 0;
          TELNET_OPT_ECHO          = 1;
          TELNET_OPT_SGA           = 3;
          TELNET_OPT_NAMS          = 4;
          TELNET_OPT_STATUS        = 5;  
          TELNET_OPT_TM            = 6;
          TELNET_OPT_RCTE          = 7;
          TELNET_OPT_NAOL          = 8;
          TELNET_OPT_NAOP          = 9;
          TELNET_OPT_NAOCRD        = 10;
          TELNET_OPT_NAOHTS        = 11;
          TELNET_OPT_NAOHTD        = 12;
          TELNET_OPT_NAOFFD        = 13;
          TELNET_OPT_NAOVTS        = 14;
          TELNET_OPT_NAOVTD        = 15;
          TELNET_OPT_NAOLFD        = 16;
          TELNET_OPT_XASCII        = 17;
          TELNET_OPT_LOGOUT        = 18;
          TELNET_OPT_BM            = 19;
          TELNET_OPT_DET           = 20;
          TELNET_OPT_SUPDUP        = 21;
          TELNET_OPT_SUPDUPOUTPUT  = 22;
          TELNET_OPT_SNDLOC        = 23;
          TELNET_OPT_TTYPE         = 24;
          TELNET_OPT_EOR           = 25;
          TELNET_OPT_TUID          = 26;
          TELNET_OPT_OUTMRK        = 27;
          TELNET_OPT_TTYLOC        = 28;
          TELNET_OPT_3270REGIME    = 29;
          TELNET_OPT_X3PAD         = 30;
          TELNET_OPT_NAWS          = 31;
          TELNET_OPT_TSPEED        = 32;
          TELNET_OPT_LFLOW         = 33;
          TELNET_OPT_LINEMODE      = 34;
          TELNET_OPT_XDISPLOC      = 35;
          TELNET_OPT_OLD_ENVIRON   = 36;
          TELNET_OPT_AUTHENTICATION= 37;
          TELNET_OPT_ENCRYPT       = 38;
          TELNET_OPT_NEW_ENVIRON   = 39;
          TELNET_OPT_CHARSET       = 42;

    class function TelnetCommandToString(const ACommand: Byte): string; static;
    class function TelnetOptionToString(Option: Byte): string; static;
    class function SendISOptionDataToString(const aOptionValue: byte;
      SubCommand: String): string; static;
    class function LFlowOptionToString(Option: Byte): string; static;
    class procedure ExtractDataFromLTCPPayload(const LTCPPayLoad: PByte;
      const LDataSize,aStartLevel: Integer; AListDetail: TListHeaderString); static;
    class function CommandStatusToString(const aStatus: Uint8): string;
  protected
  public
    /// <summary>
    /// Returns the default Telnet port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the Telnet protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the Telnet protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the Telnet protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; override;            
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean; override;
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolTelnet }
class function TWPcapProtocolTelnet.DefaultPort: Word;
begin
  Result := PROTO_TELNET_PORT;
end;

class function TWPcapProtocolTelnet.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_TELNET
end;

class function TWPcapProtocolTelnet.ProtoName: String;
begin
  Result := 'TerminaL Network';
end;

class function TWPcapProtocolTelnet.AcronymName: String;
begin
  Result := 'Telnet';
end;

class function TWPcapProtocolTelnet.IsValid(const aPacket: PByte;aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;

var LTCPPtr: PTCPHdr;
begin
  Result := False;    
  if not HeaderTCP(aPacket,aPacketSize,LTCPPtr) then exit;   
  if not PayLoadLengthIsValid(LTCPPtr,aPacket,aPacketSize) then  Exit;

  Result := IsValidByDefaultPort(DstPort(LTCPPtr),SrcPort(LTCPPtr),aAcronymName,aIdProtoDetected)
  
end;

class function TWPcapProtocolTelnet.TelnetCommandToString(const ACommand: Byte): string;
begin
  case ACommand of
    TELNET_CMD_SE    : Result := 'End of subnegotiation';
    TELNET_CMD_NOP   : Result := 'No operation';
    TELNET_CMD_DM    : Result := 'Data mark';
    TELNET_CMD_BRK   : Result := 'Break';
    TELNET_CMD_IP    : Result := 'Interrupt process';
    TELNET_CMD_AO    : Result := 'Abort output';
    TELNET_CMD_AYT   : Result := 'Are you there';
    TELNET_CMD_EC    : Result := 'Erase character';
    TELNET_CMD_EL    : Result := 'Erase line';
    TELNET_CMD_GA    : Result := 'Go ahead';
    TELNET_CMD_SB    : Result := 'Subnegotiation';
    TELNET_CMD_WILL  : Result := 'Will';
    TELNET_CMD_WONT  : Result := 'Won''t';
    TELNET_CMD_DO    : Result := 'Do';
    TELNET_CMD_DONT  : Result := 'Don''t';
    TELNET_CMD_EOR   : Result := 'End of record';
    TELNET_CMD_ABORT : Result := 'Abort process';
    TELNET_CMD_SUSP  : Result := 'Suspend process';
    TELNET_CMD_EOF   : Result := 'End of file';
    TELNET_CMD_EW    : Result := 'Erase word';
    TELNET_CMD_CBT   : Result := 'Cursor back tab';
    TELNET_CMD_SRS   : Result := 'Send/receive start';
    TELNET_CMD_SDS   : Result := 'Send/receive stop';
    TELNET_CMD_SIM   : Result := 'Subnegotiation interrupt';
    TELNET_CMD_SAK   : Result := 'Secure attention';
  else 
    Result := 'Unknown';
  end;
end;


class function TWPcapProtocolTelnet.TelnetOptionToString(Option: Byte): string;
begin
  case Option of
    TELNET_OPT_BINARY         : Result := 'Binary';
    TELNET_OPT_ECHO           : Result := 'Echo';
    TELNET_OPT_SGA            : Result := 'Suppress Go Ahead';
    TELNET_OPT_STATUS         : Result := 'Status';
    TELNET_OPT_TM             : Result := 'Timing mark';
    TELNET_OPT_TTYPE          : Result := 'Terminal type';
    TELNET_OPT_NAWS           : Result := 'Negotiate about window size';
    TELNET_OPT_CHARSET        : Result := 'Charset';
    TELNET_OPT_TSPEED         : Result := 'Terminal speed';
    TELNET_OPT_LFLOW          : Result := 'Remote flow control';
    TELNET_OPT_LINEMODE       : Result := 'Linemode';
    TELNET_OPT_NEW_ENVIRON    : Result := 'New environment option';
    TELNET_OPT_OLD_ENVIRON    : Result := 'Old environment option';
    TELNET_OPT_XDISPLOC       : Result := 'X Display Location';
    TELNET_OPT_AUTHENTICATION : Result := 'Authentication Option';
    TELNET_OPT_ENCRYPT        : Result := 'Encryption Option';
    TELNET_OPT_LOGOUT         : Result := 'Logout';
    TELNET_OPT_XASCII         : Result := 'x Ascii';
    TELNET_OPT_NAMS           : Result := 'Name';
    TELNET_OPT_RCTE           : Result := 'Reconnection';
    TELNET_OPT_NAOL           : Result := 'Output line width';
    TELNET_OPT_NAOP           : Result := 'Output page size';
    TELNET_OPT_NAOCRD         : Result := 'Carriage-return disposition';
    TELNET_OPT_NAOHTS         : Result := 'Horizontal tabstops';
    TELNET_OPT_NAOHTD         : Result := 'Horizontal tab disposition';
    TELNET_OPT_NAOFFD         : Result := 'Formfeed disposition';
    TELNET_OPT_NAOVTS         : Result := 'Vertical tab stops';
    TELNET_OPT_NAOVTD         : Result := 'Vertical tab disposition';
    TELNET_OPT_NAOLFD         : Result := 'Output LF disposition';
    TELNET_OPT_BM             : Result := 'Byte macro';
    TELNET_OPT_DET            : Result := 'Data Entry Terminal';
    TELNET_OPT_SUPDUP         : Result := 'SUPDUP';
    TELNET_OPT_SUPDUPOUTPUT   : Result := 'SUPDUP Output';
    TELNET_OPT_SNDLOC         : Result := 'Send Location';
    TELNET_OPT_EOR            : Result := 'End of record';
    TELNET_OPT_TUID           : Result := 'TACACS User Identification';
    TELNET_OPT_OUTMRK         : Result := 'Output Marking';
    TELNET_OPT_TTYLOC         : Result := 'Terminal Location Number';
    TELNET_OPT_3270REGIME     : Result := '3270 regime';
    TELNET_OPT_X3PAD          : Result := 'X.3 PAD';
  else
    Result := 'Unknown';
  end;
end;

class function TWPcapProtocolTelnet.LFlowOptionToString(Option: Byte): string;
CONST   LFLOW_NOT_DEFINED   = 0;
        LFLOW_SOFT_FLOW     = 1;
        LFLOW_RESTART_ANY   = 2;
        LFLOW_RESTART_XON   = 3;
        LFLOW_RESTART_XOFF  = 4;
begin
  case Option of
    LFLOW_NOT_DEFINED : Result := 'Flow control not defined';
    LFLOW_SOFT_FLOW   : Result := 'SOFT-FLOW';
    LFLOW_RESTART_ANY : Result := 'RESTART-ANY';
    LFLOW_RESTART_XON : Result := 'RESTART-XON';
    LFLOW_RESTART_XOFF: Result := 'RESTART-XOFF';
  else
    Result := 'Unknown'
  end;
end;

class function TWPcapProtocolTelnet.CommandStatusToString(const aStatus: Uint8): string;
begin
  case aStatus of
    0 : Result := 'Disable';
    1 : Result := 'Active';
  else
    Result := 'Unknown'
  end;
end;

class function TWPcapProtocolTelnet.SendISOptionDataToString(const aOptionValue: byte;SubCommand:String): string;
CONST TELNET_TTYPE_IS   = 0;
      TELNET_TTYPE_SEND = 1;
begin
  case aOptionValue of
    TELNET_TTYPE_SEND: Result := Format('Send your %s',[SubCommand.ToLower]);
    TELNET_TTYPE_IS  : Result := Format('Is my %s',[SubCommand.ToLower]);
  else
    Result := 'Unknown'
  end;  
end;

class procedure TWPcapProtocolTelnet.ExtractDataFromLTCPPayload(const LTCPPayLoad: PByte; const LDataSize,aStartLevel: Integer; AListDetail: TListHeaderString);
var LCurrentPos: Integer;
    LDataStr   : AnsiString;
    LChar      : AnsiChar;
begin
  LDataStr    := String.Empty;
  LCurrentPos := 0;

  while LCurrentPos < LDataSize do
  begin
    if LTCPPayLoad[LCurrentPos] = TELNET_CMD_IAC then
    begin
      Inc(LCurrentPos);
      if LCurrentPos >= LDataSize then
        Break; // IAC byte was last in the buffer, no more data to read
    end
    else
    begin
      LChar := AnsiChar(LTCPPayLoad[LCurrentPos]);
      if (LChar = #10) or (LChar = #13) then
      begin
        if LDataStr <>'' then
        begin
          LDataStr := LDataStr + '\n\r'; // replace newlines with spaces
          AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Data',[AcronymName]), 'Data:',LDataStr, @LDataStr,Length(LDataStr)));      
          LDataStr := String.Empty;          
        end;
      end  
      else
        LDataStr := LDataStr + LChar;
    end;
    Inc(LCurrentPos);
  end;
  if LDataStr <> ''   then
    AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Data',[AcronymName]), 'Data:',LDataStr, @LDataStr,Length(LDataStr)));      
end;

class function TWPcapProtocolTelnet.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LTCPPayLoad        : PByte;
    LTCPPHdr           : PTCPHdr;
    LDataSize          : Integer;
    LCurrentPos        : Integer;
    LCommand           : Byte;
    LOption            : Byte;
    LSubCommand        : Byte;
    LIsCommand         : Boolean;
    LIsOption          : Boolean;
    LIsSubCommand      : Boolean;
    LValueWord         : PWord;
    LValueByte         : Byte;    
    LValueBuffer       : PByte;
    LBckCurrentPos     : Integer;
begin
  Result := False;

  if not HeaderTCP(aPacketData,aPacketSize,LTCPPHdr) then Exit;
  FIsFilterMode := aIsFilterMode;
  LTCPPayLoad   := GetTCPPayLoad(aPacketData,aPacketSize);
  LDataSize     := TCPPayLoadLength(LTCPPHdr,aPacketData,aPacketSize);
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, nil,LDataSize));

  LCurrentPos := 0;
  while LCurrentPos < LDataSize do
  begin
    LCommand  := LTCPPayLoad[LCurrentPos];
    if Lcommand = TELNET_CMD_IAC then
    begin
      Inc(LCurrentPos);
      LCommand := LTCPPayLoad[LCurrentPos];      
    end
    else
    begin
      if LCurrentPos = 0 then
      begin
        {Data}
        ExtractDataFromLTCPPayload(LTCPPayLoad, LDataSize,aStartLevel,AListDetail);


        break;       
      end;
    end;
      
    LIsCommand     := InRange(LCommand,TELNET_CMD_SE,TELNET_CMD_DONT);
    LIsOption      := InRange(LCommand,TELNET_OPT_BINARY,TELNET_OPT_CHARSET);
    LIsSubCommand  := (LCommand = TELNET_CMD_SB);
  
    if LIsCommand then
    begin
      AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Command',[AcronymName]), 'Command:', TelnetCommandToString(LCommand), @LCommand, SizeOf(LCommand), LCommand ));
      Inc(LCurrentPos);
    end
    else if LIsOption then
    begin
      LOption := LTCPPayLoad[LCurrentPos];
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Command.Subcommand',[AcronymName]), 'Subcommand:', TelnetOptionToString(LOption), @LOption, SizeOf(LOption), LOption ));
      Inc(LCurrentPos);
      continue;
    end 
    else if not LIsSubCommand then
      Inc(LCurrentPos);

    if LIsSubCommand then
    begin
      LSubCommand := LTCPPayLoad[LCurrentPos];
         
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Command.SubCommand',[AcronymName]), 'SubCommand:', TelnetOptionToString(LSubCommand), @LSubCommand, SizeOf(LSubCommand) , LSubCommand));      
      Inc(LCurrentPos);

      case LSubCommand of
        TELNET_OPT_NAWS :
          begin  
            ParserUint16Value(LTCPPayLoad,aStartLevel+2,LDataSize,Format('%s.Command.Height',[AcronymName]), 'Height:',AListDetail,nil,True,LCurrentPos);          
            ParserUint16Value(LTCPPayLoad,aStartLevel+2,LDataSize,Format('%s.Command.Width',[AcronymName]), 'Width:',AListDetail,nil,True,LCurrentPos);          
          end;
        TELNET_OPT_TTYPE,
        TELNET_OPT_LFLOW,
        TELNET_OPT_XDISPLOC:
          begin
             LValueByte := LTCPPayLoad[LCurrentPos];
                          
             if TELNET_OPT_LFLOW = LSubCommand then
                AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Command.Command',[AcronymName]), 'Command:', LFlowOptionToString(LValueByte),@LValueByte,SizeOf(LValueByte), LValueByte ))
             else
               AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Command.OptionData',[AcronymName]), 'Option data:', SendISOptionDataToString(LValueByte,TelnetOptionToString(LSubCommand)),@LValueByte,SizeOf(LValueByte), LValueByte ));    
             inc(LCurrentPos);
             
             LBckCurrentPos := LCurrentPos;
             if LTCPPayLoad[LBckCurrentPos] <> TELNET_CMD_IAC then
             begin
               {Found value string}
                while (LCurrentPos < LDataSize) and (LTCPPayLoad[LCurrentPos] <> TELNET_CMD_IAC) do
                  inc(LCurrentPos);               

                GetMem(LValueBuffer,LCurrentPos-LBckCurrentPos);
                Try                          
                  Move(LTCPPayLoad[LBckCurrentPos],LValueBuffer^,LCurrentPos-LBckCurrentPos);
                  AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Command.Command.Value',[AcronymName]), 'Value:',AnsiString(PAnsiChar(LValueBuffer)),LValueBuffer,LCurrentPos-LBckCurrentPos));   
                Finally                                                                                         
                  FreeMem(LValueBuffer);
                End;                
             end;             
          end;
        TELNET_OPT_ECHO,
        TELNET_OPT_SGA:
          begin
            ParserUint8Value(LTCPPayLoad,aStartLevel+2,LDataSize,Format('%s.Command.Status',[AcronymName]), 'Status:',AListDetail,CommandStatusToString,True,LCurrentPos);   

            LBckCurrentPos := LCurrentPos;
            if LTCPPayLoad[LBckCurrentPos] <> TELNET_CMD_IAC then
            begin
             {Found value string}
              while (LCurrentPos < LDataSize) and (LTCPPayLoad[LCurrentPos] <> TELNET_CMD_IAC) do
                inc(LCurrentPos);               

              GetMem(LValueBuffer,LCurrentPos-LBckCurrentPos);
              Try                          
                Move(LTCPPayLoad[LBckCurrentPos],LValueBuffer^,LCurrentPos-LBckCurrentPos);
                AListDetail.Add(AddHeaderInfo(aStartLevel+3, Format('%s.Command.Status.Value',[AcronymName]), 'Value:',AnsiString(PAnsiChar(LValueBuffer)),LValueBuffer,LCurrentPos-LBckCurrentPos));   
              Finally                                                                                         
                FreeMem(LValueBuffer);
              End;                
            end;               
          end
      else
          begin   
            LBckCurrentPos := LCurrentPos;

            while (LCurrentPos < LDataSize) and (LTCPPayLoad[LCurrentPos] <> TELNET_CMD_IAC) do
              inc(LCurrentPos);

            GetMem(LValueBuffer,LCurrentPos-LBckCurrentPos);
            Try
              Move(LTCPPayLoad[LBckCurrentPos],LValueBuffer^,LCurrentPos-LBckCurrentPos);
              AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Command.OptionData',[AcronymName]), 'Option data:', string.Join('',DisplayHexData(LValueBuffer,LCurrentPos-LBckCurrentPos,false)).Trim,nil,0));   
            Finally                                                                                         
              FreeMem(LValueBuffer);
            End;
          end;      
      end;
    end
  end;  
  Result := True;
end;



end.
                                                 
