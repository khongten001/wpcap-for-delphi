unit wpcap.Protocol.NBNS;

interface

uses
  wpcap.Protocol.DNS, wpcap.Conts, wpcap.Types, wpcap.BufferUtils, System.StrUtils,
  WinApi.Windows, System.Generics.Defaults, System.SysUtils, System.Variants,Wpcap.IpUtils,
  System.Math, winsock, wpcap.StrUtils, System.Generics.Collections;

type

   {
    https://datatracker.ietf.org/doc/html/rfc1001
    https://www.ietf.org/rfc/rfc1002.txt



                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   + ------                                                ------- +
   |                            HEADER                             |
   + ------                                                ------- +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                       QUESTION ENTRIES                        /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                    ANSWER RESOURCE RECORDS                    /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                  AUTHORITY RESOURCE RECORDS                   /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                  ADDITIONAL RESOURCE RECORDS                  /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         NAME_TRN_ID           | OPCODE  |   NM_FLAGS  | RCODE |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          QDCOUNT              |           ANCOUNT             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          NSCOUNT              |           ARCOUNT             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


   }

    

  TStatisticsRSS = record 
    UnitID                     : Cardinal;
    UnitIDContinued            : Word;
    Jumpers                    : Byte;
    TestResult                 : Byte;
    VersionNumber              : Word;
    PeriodOfStatistics         : Word;
    NumberOfCRCs               : Word;
    NumberAlignmentErrors      : Word;
    NumberOfCollisions         : Word;
    NumberSendAborts           : Word;
    NumberGoodSends            : Cardinal;
    NumberGoodReceives         : Cardinal;
    NumberRetransmits          : Word;
    NumberNoResourceConditions : Word;
    NumberFreeCommandBlocks    : Word;
    TotalNumberCommandBlocks   : Word;
    MaxTotalNumberCommandBlocks: Word;
    NumberPendingSessions      : Word;
    MaxNumberPendingSessions   : Word;
    MaxTotalSessionsPossible   : Word;
    SessionDataPacketSize      : Word;
  end; 

   
  /// <summary>
  /// Represents the NetBIOS Name Service(NBNS) protocol for WireShark.
  /// </summary>
  TWPcapProtocolNBNS = class(TWPcapProtocolDNS)
  private

  
    class function NBNSNameToString(const aName:String): string;
    class procedure ParseAnswerName(const aPacket: TBytes;aMaxName:Integer; var aOffset,aTotalNameLen: integer; AListDetail: TListHeaderString);static;
    class function OwnerNodeTypeToStr(aFlags: Byte): String; static;
  protected
    class function ApplyConversionName(const aName: AnsiString): AnsiString;override;  
    class function DecodeDNS_RSS_SRV(const aPacket: TBytes; var aOffset,aTotalNameLen: integer; AListDetail: TListHeaderString): AnsiString; override;        
    class function DecodeDNS_RSS_NIMLOC(const aPacket: TBytes; var aOffset,aTotalNameLen: integer; AListDetail: TListHeaderString): AnsiString; override;    
  public
    /// <summary>
    /// Returns the default port number used by the NBNS protocol.
    /// </summary>
    class function DefaultPort: Word; override;

    /// <summary>
    /// Return Intenal protocol ID
    /// </summary>
    class function IDDetectProto: byte; override;

    /// <summary>
    /// Returns the name of the protocol for the NBNS protocol
    /// </summary>
    class function ProtoName: String; override;

    /// <summary>
    /// Returns the acronym name for the NBNS protocol.
    /// </summary>
    class function AcronymName: String; override;
    /// <summary>
    /// This function returns a TListHeaderString of strings representing the fields in the NBNS header. 
    //  It takes a pointer to the packet data and an integer representing the size of the packet as parameters, and returns a dictionary of strings.
    /// </summary>    
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; override;  


    /// <summary>
    ///  Returns the NBNS flags as a string.
    /// </summary>
    /// <param name="Flags">
    ///   The NBNS flags to convert.
    /// </param>
    /// <param name="AListDetail">
    ///   The list of header details to include in the output string.
    /// </param>
    /// <NBNS>
    ///   A string representation of the DNS flags.
    /// </returns>    
    class function GetDNSFlags(aFlags: Word; AListDetail: TListHeaderString): string;override;
    
    /// <summary>
    ///  Returns a string representation of a NBNS question class.
    /// </summary>
    /// <param name="aType">
    ///   The NBNS question class to convert.
    /// </param>
    /// <returns>
    ///   A string representation of the NBNS question class.
    /// </returns>
    class function QuestionClassToStr(aType: Word): string;override;      
end;


implementation

class function TWPcapProtocolNBNS.DefaultPort: Word;
begin
  Result := PROTO_NBNS_PORT;
end;

class function TWPcapProtocolNBNS.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_NBNS;
end;

class function TWPcapProtocolNBNS.ProtoName: String;
begin
  Result := 'NetBIOS Name Service'
end;

class function TWPcapProtocolNBNS.AcronymName: String;
begin
  Result := 'NBNS';
end;

class function TWPcapProtocolNBNS.NBNSNameToString(const aName:String): string;
var i          : Integer;
    LFirstChar : Char;
    LSecondChar: Char;
begin
  (*
    The algorithm used to encode NetBIOS names is as follows:

    Each half-octet of the NetBIOS name is encoded into 1 byte of the 32-byte field.
    The first half-octet is encoded into the first byte, the second half- octet into
    the second byte, and so on. Each 4-bit, half-octet of the NetBIOS name is
    treated as an 8-bit, right-adjusted, zero-filled binary number. This number is
    added to the value of the ASCII character 'A' (hexadecimal 41). The resulting
    8-bit number is stored in the appropriate byte.

    This encoding results in a NetBIOS name being represented as a sequence of 32
    ASCII, upper-case characters from the set {A,B,C...N,O,P}. The NetBIOS scope
    identifier is a valid domain name (without a leading dot).

    An ASCII dot (2E hexadecimal) and the scope identifier are appended to the
    encoded form of the NetBIOS name, the result forming a valid domain name.

    For example, the NetBIOS name "THE NETBIOS NAME" in the NetBIOS scope
    "SCOPE.ID.COM" would be represented at level one by the ASCII character string:

      FEEIEFCAEOEFFEECEJEPFDCAEOEBENEF.SCOPE.ID.COM

    The following is a list of characters and their corresponding encoded ASCII and
    hex values:

      Character   ASCII Code    Hex Code
      ----------------------------------

      A            EB            45 42
      B            EC            45 43
      C            ED            45 44
      D            EE            45 45
      E            EF            45 46
      F            EG            45 47
      G            EH            45 48
      H            EI            45 49
      I            EJ            45 4A
      J            EK            45 4B
      K            EL            45 4C
      L            EM            45 4D
      M            EN            45 4E
      N            EO            45 4F
      O            EP            45 50
      P            FA            46 41
      Q            FB            46 42
      R            FC            46 43
      S            FD            46 44
      T            FE            46 45
      U            FF            46 46
      V            FG            46 47
      W            FH            46 48
      X            FI            46 49
      Y            FJ            46 4A
      Z            FK            46 4B

      0            DA            44 41
      1            DB            44 42
      2            DC            44 43
      3            DD            44 44
      4            DE            44 45
      5            DF            44 46
      6            DG            44 47
      7            DH            44 48
      8            DI            44 49
      9            DJ            44 4A

      <space>      CA            43 41
      !            CB            43 42
      "            CC            43 43
      #            CD            43 44
      $            CE            43 45
      %            CF            43 46
      &            CG            43 47
      '            CH            43 48
      (            CI            43 49
      )            CJ            43 4A
      *            CK            43 4B
      +            CL            43 4C
      ,(comma)     CM            43 4D
      -(hyphen)    CN            43 4E
      .(period)    CO            43 4F
      =            DN            44 4E
      :(colon)     DK            44 4B
      ;(semicolon) DL            44 4C
      @            EA            45 41
      ^            FO            46 4F
      _(underscore)FP            46 50
      {            HL            48 4C
      }            HN            48 4E
      ~            HO            48 4F
  *)

  Result := String.Empty;
  i      := 1;
  while i <= Length(aName) do
  begin
    LFirstChar := aName[i];
    if LFirstChar <> '.' then
    begin
      LSecondChar := aName[i+1];
      Result      := Result + Chr(((Ord(LFirstChar)-Ord('A')) shl 4) + ((Ord(LSecondChar)-Ord('A')) and $F));
      i           := i + 2;
    end
    else
      Break;
  end;
end;

class function TWPcapProtocolNBNS.IsValid(const aPacket: PByte;aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LAcronymNameTmp     : String;
    LIdProtoDetectedTmp : Byte;
begin
  Result  := inherited IsValid(aPacket,aPacketSize,LAcronymNameTmp,LIdProtoDetectedTmp);  
        
  if result then
  begin
    aAcronymName     := LAcronymNameTmp;
    aIdProtoDetected := LIdProtoDetectedTmp;
  end;    
end;

class function TWPcapProtocolNBNS.QuestionClassToStr(aType: Word): string;
begin
  Result := String.Empty;

  case aType of
    TYPE_DNS_QUESTION_NIMLOC : Result := 'NB';
    TYPE_DNS_QUESTION_SRV    : Result := 'NBSTAT';
  end;
  
  if Result.IsEmpty then  
    Result := inherited QuestionClassToStr(aType)  
  else
    Result := Format('%s [%d]',[Result,aType])    
end;

class function TWPcapProtocolNBNS.ApplyConversionName(const aName: AnsiString): AnsiString;
begin
  Try
    Result := NBNSNameToString(aName);
  Except
    Result := aName;
  End;
end;

class procedure TWPcapProtocolNBNS.ParseAnswerName(const aPacket: TBytes;aMaxName:Integer; var aOffset,aTotalNameLen: integer;AListDetail: TListHeaderString);
CONST MAX_LEN =16;
var  
   LName : String;
   I     : Integer;
   LChar : AnsiChar;
   LFlags: Byte;

   LLen: Integer;
begin

  {
   NODE_NAME Entry:

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +---                                                         ---+
   |                                                               |
   +---                    NETBIOS FORMAT NAME                  ---+
   |                                                               |
   +---                                                         ---+
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         NAME_FLAGS            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

   The NAME_FLAGS field:

                                             1   1   1   1   1   1
     0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   | G |  ONT  |DRG|CNF|ACT|PRM|          RESERVED                 |
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

   The NAME_FLAGS field is defined as:

   Symbol     Bit(s)   Description:

   RESERVED     7-15   Reserved for future use.  Must be zero (0).
   PRM             6   Permanent Name Flag.  If one (1) then entry
                       is for the permanent node name.  Flag is zero
                       (0) for all other names.
   ACT             5   Active Name Flag.  All entries have this flag
                       set to one (1).
   CNF             4   Conflict Flag.  If one (1) then name on this
                       node is in conflict.
   DRG             3   Deregister Flag.  If one (1) then this name
                       is in the process of being deleted.
   ONT           1,2   Owner Node Type:
                          00 = B node
                          01 = P node
                          10 = M node
                          11 = Reserved for future use
   G               0   Group Name Flag.
                       If one (1) then the name is a GROUP NetBIOS
                       name.
                       If zero (0) then it is a UNIQUE NetBIOS name.
  }
  
  for I := 1 to aMaxName do
  begin
    LName := String.Empty;
    LLen  := 0;    
    while true do
    begin
      LChar := AnsiChar(aPacket[aOffset]);
      Inc(aOffset);
      Inc(aTotalNameLen);
      Inc(LLen);        

      if LLen = MAX_LEN  then
      begin
        if not LName.IsEmpty then
          AListDetail.Add(AddHeaderInfo(3, Format('Name:%d:',[I]),LName.Trim, @LName, Length(LName)));
        LFlags := aPacket[aOffset];
        AListDetail.Add(AddHeaderInfo(4, 'Type:',ifthen(GetBitValue(LFlags,1)=1,'Group name','Unique name'), nil, 0));
        AListDetail.Add(AddHeaderInfo(4, 'Owner node:',OwnerNodeTypeToStr(LFlags), nil, 0)); 

        AListDetail.Add(AddHeaderInfo(4, 'Deregister:',GetBitValue(LFlags,4)=1, nil, 0));                
        AListDetail.Add(AddHeaderInfo(4, 'Conflict:',GetBitValue(LFlags,5)=1, nil, 0));
        AListDetail.Add(AddHeaderInfo(4, 'Active:',GetBitValue(LFlags,6)=1, nil, 0));
        AListDetail.Add(AddHeaderInfo(4, 'Permanent:',GetBitValue(LFlags,7)=1, nil, 0));                
        inc(aOffset,2);
        Inc(aTotalNameLen,2);  
  
        break;
      end;
      LName := LName+LChar;
      
    end;
  end;
    
end;

class function TWPcapProtocolNBNS.OwnerNodeTypeToStr(aFlags:Byte):String;
var  LOwner: Byte;
begin
  LOwner := ( aFlags  shr 5 ) and $3;
  case LOwner of
    0:  Result := 'B';          
    1:  Result := 'P';
    2:  Result := 'M';                                     
    3:  Result := 'Reserved';
  else
    Result := 'Unknown';
  end;
  Result := Format('%s [%d-%d]',[Result,LOwner,aFlags])
end;


class function TWPcapProtocolNBNS.DecodeDNS_RSS_SRV(const aPacket: TBytes;var aOffset, aTotalNameLen: integer;AListDetail: TListHeaderString): AnsiString;
var LNumberName    : Byte;
    LStatisticsRSS : TStatisticsRSS;
begin
  Result := String.Empty;
  LNumberName := aPacket[aOffset];

  { NODE STATUS RESPONSE
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         NAME_TRN_ID           |1|  0x0  |1|0|0|0|0 0|0|  0x0  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          0x0000               |           0x0001              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          0x0000               |           0x0000              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   /                            RR_NAME                            /
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        NBSTAT (0x0021)        |         IN (0x0001)           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          0x00000000                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          RDLENGTH             |   NUM_NAMES   |               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
   |                                                               |
   +                                                               +
   /                         NODE_NAME ARRAY                       /
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                                                               +
   /                           STATISTICS                          /
   +                                                               +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  }
          
  AListDetail.Add(AddHeaderInfo(3, 'Number of name:',LNumberName,PByte(@aPacket[aOffset]), SizeOf(LNumberName))); 
  Inc(aOffset, SizeOf(LNumberName));
  ParseAnswerName(aPacket,LNumberName,aOffset,aTotalNameLen,AListDetail);  

  
  {   STATISTICS Field of the NODE STATUS RESPONSE:

                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               UNIT_ID (Unique unit ID)                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       UNIT_ID,continued       |    JUMPERS    |  TEST_RESULT  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       VERSION_NUMBER          |      PERIOD_OF_STATISTICS     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       NUMBER_OF_CRCs          |     NUMBER_ALIGNMENT_ERRORS   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       NUMBER_OF_COLLISIONS    |        NUMBER_SEND_ABORTS     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       NUMBER_GOOD_SENDS                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      NUMBER_GOOD_RECEIVES                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       NUMBER_RETRANSMITS      | NUMBER_NO_RESOURCE_CONDITIONS |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  NUMBER_FREE_COMMAND_BLOCKS   |  TOTAL_NUMBER_COMMAND_BLOCKS  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |MAX_TOTAL_NUMBER_COMMAND_BLOCKS|    NUMBER_PENDING_SESSIONS    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  MAX_NUMBER_PENDING_SESSIONS  |  MAX_TOTAL_SESSIONS_POSSIBLE  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   SESSION_DATA_PACKET_SIZE    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+}

  Move(aPacket[aOffset], LStatisticsRSS, SizeOf(LStatisticsRSS));

  AListDetail.Add(AddHeaderInfo(3, 'Unit ID:', wpcapntohl(LStatisticsRSS.UnitID), @LStatisticsRSS.UnitID, SizeOf(LStatisticsRSS.UnitID)));
  AListDetail.Add(AddHeaderInfo(3, 'Unit ID, continued:', wpcapntohs(LStatisticsRSS.UnitIDContinued), @LStatisticsRSS.UnitIDContinued, SizeOf(LStatisticsRSS.UnitIDContinued)));
  AListDetail.Add(AddHeaderInfo(3, 'Jumpers:', LStatisticsRSS.Jumpers, @LStatisticsRSS.Jumpers, SizeOf(LStatisticsRSS.Jumpers)));
  AListDetail.Add(AddHeaderInfo(3, 'Test Result:', LStatisticsRSS.TestResult, @LStatisticsRSS.TestResult, SizeOf(LStatisticsRSS.TestResult)));
  AListDetail.Add(AddHeaderInfo(3, 'Version Number:', wpcapntohs(LStatisticsRSS.VersionNumber), @LStatisticsRSS.VersionNumber, SizeOf(LStatisticsRSS.VersionNumber)));
  AListDetail.Add(AddHeaderInfo(3, 'Period of Statistics:', wpcapntohs(LStatisticsRSS.PeriodOfStatistics), @LStatisticsRSS.PeriodOfStatistics, SizeOf(LStatisticsRSS.PeriodOfStatistics)));
  AListDetail.Add(AddHeaderInfo(3, 'Number of CRCs:', wpcapntohs(LStatisticsRSS.NumberOfCRCs), @LStatisticsRSS.NumberOfCRCs, SizeOf(LStatisticsRSS.NumberOfCRCs)));
  AListDetail.Add(AddHeaderInfo(3, 'Number Alignment Errors:', wpcapntohs(LStatisticsRSS.NumberAlignmentErrors), @LStatisticsRSS.NumberAlignmentErrors, SizeOf(LStatisticsRSS.NumberAlignmentErrors)));
  AListDetail.Add(AddHeaderInfo(3, 'Number of Collisions:', wpcapntohs(LStatisticsRSS.NumberOfCollisions), @LStatisticsRSS.NumberOfCollisions, SizeOf(LStatisticsRSS.NumberOfCollisions)));
  AListDetail.Add(AddHeaderInfo(3, 'Number Send Aborts:', wpcapntohs(LStatisticsRSS.NumberSendAborts), @LStatisticsRSS.NumberSendAborts, SizeOf(LStatisticsRSS.NumberSendAborts)));
  AListDetail.Add(AddHeaderInfo(3, 'Number Good Sends:', wpcapntohl(LStatisticsRSS.NumberGoodSends), @LStatisticsRSS.NumberGoodSends, SizeOf(LStatisticsRSS.NumberGoodSends)));
  AListDetail.Add(AddHeaderInfo(3, 'Number Good Receives:', wpcapntohl(LStatisticsRSS.NumberGoodReceives), @LStatisticsRSS.NumberGoodReceives, SizeOf(LStatisticsRSS.NumberGoodReceives)));
  AListDetail.Add(AddHeaderInfo(3, 'Number Retransmits:', wpcapntohs(LStatisticsRSS.NumberRetransmits), @LStatisticsRSS.NumberRetransmits, SizeOf(LStatisticsRSS.NumberRetransmits)));
  AListDetail.Add(AddHeaderInfo(3, 'Number No Resource Conditions:', wpcapntohs(LStatisticsRSS.NumberNoResourceConditions), @LStatisticsRSS.NumberNoResourceConditions, SizeOf(LStatisticsRSS.NumberNoResourceConditions)));
  AListDetail.Add(AddHeaderInfo(3, 'Number Free Command Blocks:', wpcapntohs(LStatisticsRSS.NumberFreeCommandBlocks), @LStatisticsRSS.NumberFreeCommandBlocks, SizeOf(LStatisticsRSS.NumberFreeCommandBlocks)));
  AListDetail.Add(AddHeaderInfo(3, 'Total Number Command Blocks:', wpcapntohs(LStatisticsRSS.TotalNumberCommandBlocks), @LStatisticsRSS.TotalNumberCommandBlocks, SizeOf(LStatisticsRSS.TotalNumberCommandBlocks)));
  AListDetail.Add(AddHeaderInfo(3, 'Max Total Number Command Blocks:', wpcapntohs(LStatisticsRSS.MaxTotalNumberCommandBlocks), @LStatisticsRSS.MaxTotalNumberCommandBlocks, SizeOf(LStatisticsRSS.MaxTotalNumberCommandBlocks)));
  AListDetail.Add(AddHeaderInfo(3, 'Number Pending Sessions:', wpcapntohs(LStatisticsRSS.NumberPendingSessions), @LStatisticsRSS.NumberPendingSessions, SizeOf(LStatisticsRSS.NumberPendingSessions)));
  AListDetail.Add(AddHeaderInfo(3, 'Max Number Pending Sessions:', wpcapntohs(LStatisticsRSS.MaxNumberPendingSessions), @LStatisticsRSS.MaxNumberPendingSessions, SizeOf(LStatisticsRSS.MaxNumberPendingSessions)));
  AListDetail.Add(AddHeaderInfo(3, 'Max Total Sessions Possible:', wpcapntohs(LStatisticsRSS.MaxTotalSessionsPossible), @LStatisticsRSS.MaxTotalSessionsPossible, SizeOf(LStatisticsRSS.MaxTotalSessionsPossible)));
  AListDetail.Add(AddHeaderInfo(3, 'Session Data Packet Size:', wpcapntohs(LStatisticsRSS.SessionDataPacketSize), @LStatisticsRSS.SessionDataPacketSize, SizeOf(LStatisticsRSS.SessionDataPacketSize)));

end;

class function TWPcapProtocolNBNS.GetDNSFlags(aFlags: Word;AListDetail: TListHeaderString): string;
var LtmpResult       : String;
    LtmpBooleanValue : Boolean;
    LByte0           : Byte;
    LtmpValue        : Byte;
    LisQuery         : Boolean;    
begin
  Result := String.Empty;
  LByte0 := GetByteFromWord(aFlags,0);

  {

       0   1   2   3   4
     +---+---+---+---+---+
     | R |    OPCODE     |            
     +---+---+---+---+---+
       Symbol     Bit(s)   Description

       R               0   RESPONSE flag:
                             if bit == 0 then request packet
                             if bit == 1 then response packet.
  }
  LisQuery := GetBitValue(LByte0,1) =  0;
  if LisQuery then
  begin
    Result := 'Message is query'; // Message is a query
    AListDetail.Add(AddHeaderInfo(2,'Response:','Message is query',nil,0));
  end  
  else
  begin
    Result := 'Message is response'; // Message is a response
    AListDetail.Add(AddHeaderInfo(2,'Response:','Message is response',nil,0));       
  end;

  {
     Symbol     Bit(s)   Description

     OPCODE        1-4   Operation specifier:
                           0 = query
                           5 = registration
                           6 = release
                           7 = WACK
                           8 = refresh        
  }

  LtmpResult := String.Empty;
  LtmpValue  := (LByte0 shr 3) and $F;
  case LtmpValue of
    0 : LtmpResult := 'Query';
    5 : LtmpResult := 'Registration';
    6 : LtmpResult := 'release'; 
    7 : LtmpResult := 'WACK'; 
    8 : LtmpResult := 'refresh'; 
  else
    LtmpResult := 'Reserved'; // Reserved
  end;

  if not LtmpResult.IsEmpty then
  begin
    Result := Format('%s, %s',[Result,LtmpResult]);
    AListDetail.Add(AddHeaderInfo(2,'OPCode:',LtmpResult,nil,0));  
  end;

  {
    5   6   7   8   1  2   3
   +---+---+---+---+---+---+---+
   |AA |TC |RD |RA | 0 | 0 | B |
   +---+---+---+---+---+---+---+
  }
  
  {
  AA Authoritative Answer - this bit is valid in responses,
     and specifies that the responding name server is an
     authority for the domain name in question section.

     Note that the contents of the answer section may have
     multiple owner names because of aliases.  The AA bit
     corresponds to the name which matches the query name, or
     the first owner name in the answer section.
  }
  if not LisQuery then  
  begin
    LtmpBooleanValue :=  GetBitValue(LByte0,6)=1;
    AListDetail.Add(AddHeaderInfo(2,'Authoritative answer:',LtmpBooleanValue,nil,0));
    Result := Format('%s, Authoritative answer %s',[result,BoolToStr(LtmpBooleanValue,True)]);
  end;

  {
  TC  TrunCation - specifies that this message was truncated
      due to length greater than that permitted on the
      transmission channel.

  }
  LtmpBooleanValue :=  GetBitValue(LByte0,7)=1;
  AListDetail.Add(AddHeaderInfo(2,'Truncated:',LtmpBooleanValue,nil,0));
  Result := Format('%s, Truncated %s',[result,BoolToStr(LtmpBooleanValue,True)]);  

  {
  RD  Recursion Desired - this bit may be set in a query and
      is copied into the response.  If RD is set, it directs
      the name server to pursue the query recursively.
      Recursive query support is optional.
  }
  LtmpBooleanValue :=  GetBitValue(LByte0,8)=1;
  AListDetail.Add(AddHeaderInfo(2,'Recursion Desired:',LtmpBooleanValue,nil,0));
  Result := Format('%s, Recursion Desired %s',[result,BoolToStr(LtmpBooleanValue,True)]);  
  LByte0 := GetByteFromWord(aFlags,1);
  {
  RA Recursion Available - this be is set or cleared in a
     response, and denotes whether recursive query support is
     available in the name server.
  }
  if not LisQuery then
  begin
    LtmpBooleanValue :=  GetBitValue(LByte0,1)=1;
    AListDetail.Add(AddHeaderInfo(2,'Recursion available:',LtmpBooleanValue,nil,0));
    Result := Format('%s, Recursion available %s',[result,BoolToStr(LtmpBooleanValue,True)]);
  end;



  {
   B  Broadcast Flag.
        = 1: packet was broadcast or multicast
        = 0: unicast
  }  

  LtmpBooleanValue :=  GetBitValue(LByte0,4)=1;
  AListDetail.Add(AddHeaderInfo(2,'Broadcast:',LtmpBooleanValue,nil,0));
  Result := Format('%s, Broadcast available %s',[result,BoolToStr(LtmpBooleanValue,True)]); 

  if not LisQuery then
  begin
    LtmpValue  := GetLastNBit(LByte0,4);
    LtmpResult := String.Empty;

    case LtmpValue of
      0: LtmpResult := 'Response code: No error';        // No error condition
      1: LtmpResult := 'Response code: Format error';    // The name server was unable to interpret the query
      2: LtmpResult := 'Response code: Server failure';  // The name server was unable to process this query due to a problem with the name server
      3: LtmpResult := 'Response code: Name error';      // Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist
      4: LtmpResult := 'Response code: Not implemented'; // The name server does not support the requested kind of query
      5: LtmpResult := 'Response code: Refused';         // The name server refuses to perform the specified operation for policy reasons
    end;

    if not LtmpResult.IsEmpty then
    begin
      Result := Format('%s, %s',[Result,LtmpResult]);
      AListDetail.Add(AddHeaderInfo(2,'Response code:',LtmpResult.Replace('Response code:',String.Empty).Trim,nil,0));
    end;       
  
  end;
   
end;

class function TWPcapProtocolNBNS.DecodeDNS_RSS_NIMLOC(const aPacket: TBytes;var aOffset, aTotalNameLen: integer;AListDetail: TListHeaderString): AnsiString;
var LByte0        : Byte;
    LCardinalTmp  : Cardinal;
begin
{
                                             1   1   1   1   1   1
     0   1   2   3   4   5   6   7   8   9   0   1   2   3   4   5
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
   | G |  ONT  |                RESERVED                           |
   +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+

   Symbol     Bit(s)   Description:

   RESERVED     3-15   Reserved for future use.  Must be zero (0).
   ONT           1,2   Owner Node Type:
                          00 = B node
                          01 = P node
                          10 = M node
                          11 = Reserved for future use
                       For registration requests this is the
                       claimant's type.
                       For responses this is the actual owner's
                       type.

   G               0   Group Name Flag.
                       If one (1) then the RR_NAME is a GROUP
                       NetBIOS name.
                       If zero (0) then the RR_NAME is a UNIQUE
                       NetBIOS name.

   The NB_ADDRESS field of the RESOURCE RECORD RDATA field for
   RR_TYPE of "NB" is the IP address of the name's owner.}

  Result := String.Empty;
  LByte0 := aPacket[aOffset];
   
  AListDetail.Add(AddHeaderInfo(3,'Type:',ifthen(GetBitValue(LByte0,1) = 1,'Group name','Unique name'),@LByte0,1));
  AListDetail.Add(AddHeaderInfo(3, 'Owner node:',OwnerNodeTypeToStr(LByte0), @LByte0, 1));   
  Inc(aOffset,2);
  Inc(aTotalNameLen,2);
  Move(aPacket[aOffset], LCardinalTmp, SizeOf(cardinal));  
  AListDetail.Add(AddHeaderInfo(3, 'Addr:',intToIPV4(LCardinalTmp), @LCardinalTmp,SizeOf(LCardinalTmp)));     
  Inc(aOffset,2);
  Inc(aTotalNameLen,2); 
end;

end.
