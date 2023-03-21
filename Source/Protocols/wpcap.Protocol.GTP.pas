unit wpcap.Protocol.GTP;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,wpcap.StrUtils,
  Wpcap.protocol.UDP, WinApi.Windows,wpcap.BufferUtils,Variants,idGlobal,wpcap.IPUtils;

type
  { https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol}
   {
    RFC 5516: https://tools.ietf.org/html/rfc5516.
   }

  TGTPHeaderV1 = record
     Flags       : Byte;
     MessageType : Byte;
     MessageLen  : Word;
     TEID        : Cardinal;
  end;
  PTGTPHeaderV1 = ^TGTPHeaderV1;

  TGTPHeaderV2 = record
     Flags       : Byte;
     MessageType : Byte;
     MessageLen  : Word;     
  end;
  PTGTPHeaderV2 = ^TGTPHeaderV2;  

  TGTPHeaderV3 = record
     Flags       : Byte;
  end;
  PTGTPHeaderV3 = ^TGTPHeaderV3;    

  {
GTP_ECHO_REQUEST (1) e GTP_ECHO_RESPONSE (2): RFC 4898 - https://tools.ietf.org/html/rfc4898
GTP_ERROR_INDICATION (26): RFC 4898 - https://tools.ietf.org/html/rfc4898
GTP_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION (31): RFC 5512 - https://tools.ietf.org/html/rfc5512
GTP_END_MARKER (254): RFC 5777 - https://tools.ietf.org/html/rfc5777
https://www.etsi.org/deliver/etsi_ts/129200_129299/129274/14.05.00_60/ts_129274v140500p.pdf

}


  
  /// <summary>
  /// The GTP protocol implementation class.
  /// </summary>
  TWPcapProtocolGTP = Class(TWPcapProtocolBaseUDP)
  private
    CONST
    GTP_ECHO_REQUEST                             = 1;
    GTP_ECHO_RESPONSE                            = 2;
    GTP_ERROR_INDICATION                         = 26;
    GTP_RELEASE_ACCESS_BEARERS_REQUEST           = 28;    
    GTP_RELEASE_ACCESS_BEARERS_RESPONSE          = 29;
    GTP_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION = 31;
    GTP_CREATE_SESSION_REQUEST                   = 32;  //IMSI , MSISDN MCC  E CELL
    GTP_CREATE_SESSION_RESPONSE                  = 33;
    GTP_MODIFY_BEARER_REQUEST                    = 34;  //User locaton info/RAT
    GTP_MODIFY_BEARER_RESPONSE                   = 35;
    GTP_DELETE_SESSION_REQUEST                   = 36;
    GTP_DELETE_SESSION_RESPONSE                  = 37;  //OK
    GTP_DELETE_BEARER_REQUEST                    = 38;
    GTP_DELETE_BEARER_RESPONSE                   = 39;    
    GTP_CREATE_BEARER_REQUEST                    = 95;
    GTP_CREATE_BEARER_RESPONSE                   = 96;
    GTP_UPDATE_BEARER_REQUEST                    = 98;
    GTP_UPDATE_BEARER_RESPONSE                   = 99;  
    GTP_RAN_INFORMATION_RELATIVE_CAPACITY        = 142; 
    GTP_CREATE_INDIRECT_DATA_FW_TUNNEL_REQUEST   = 166;     
    GTP_CREATE_INDIRECT_DATA_FW_TUNNEL_RESPONSE  = 167; 
    GTP_DELETE_INDIRECT_DATA_FW_TUNNEL_REQUEST   = 168; //Nothing
    GTP_DELETE_INDIRECT_DATA_FW_TUNNEL_RESPONSE  = 169; 
    GTP_RELEASE_ACCESS_BEAR_REQUEST              = 170; //Nothing    
    GTP_RELEASE_ACCESS_BEAR_RESPONSE             = 171; //OK
    GTP_END_USER_SERVICE_ACKNOWLEDGEMENT         = 176;
    GTP_END_USER_SERVICE_REJECT                  = 177;
    GTP_DATA_RECORD_TRANSFER                     = 215;
    GTP_END_MARKER                               = 254;
    
    class function ProtoTypeToString(const aProtoType: Byte): String; static;
    class function MessageTypeToString(aMsgType: Byte): String; static;
  protected
  public
    /// <summary>
    /// Returns the default GTP port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the GTP protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the GTP protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the GTP protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString): Boolean; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; override;        
  end;


implementation

uses wpcap.Level.Ip;

{ TWPcapProtocolGTP }
class function TWPcapProtocolGTP.DefaultPort: Word;
begin
  Result := PROTO_GTP_PORT;
end;

class function TWPcapProtocolGTP.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_GTP
end;

class function TWPcapProtocolGTP.ProtoName: String;
begin
  Result := 'GPRS Tunnelling Protocol';
end;

class function TWPcapProtocolGTP.IsValid(const aPacket: PByte;aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;
var LUDPPPtr: PUDPHdr;
begin
  Result  := inherited IsValid(aPacket,aPacketSize,aAcronymName,aIdProtoDetected);  

  if not HeaderUDP(aPacket,aPacketSize,LUDPPPtr) then exit;
  
  if not Result then
    Result := IsValidByPort(PROTO_GTP_C_PORT,DstPort(LUDPPPtr),SrcPort(LUDPPPtr),aAcronymName,aIdProtoDetected);
  if not Result then
    Result := IsValidByPort(PROTO_GTP_U_PORT,DstPort(LUDPPPtr),SrcPort(LUDPPPtr),aAcronymName,aIdProtoDetected);    
end;

class function TWPcapProtocolGTP.AcronymName: String;
begin
  Result := 'GTP';
end;

class function TWPcapProtocolGTP.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString): Boolean;
var LUDPPayLoad        : PByte;
    LPUDPHdr           : PUDPHdr;
    LVersion           : Byte;
    LGTPHeaderV1       : PTGTPHeaderV1;
    LGTPHeaderV2       : PTGTPHeaderV2;
    LGTPHeaderV3       : PTGTPHeaderV3;  
    LCurrentPos        : Integer;    
    LByteValue         : Byte;
    LWordValue         : Word;   
    LCardinalValue     : Cardinal;          
    LIn64Value         : UInt64;
    LMessageType       : Byte;
    LPayLoadLen        : Integer;
    LBytes             : TidBytes;

    Procedure AddCause(aIndex:integer);
    begin
        AListDetail.Add(AddHeaderInfo(aIndex+1,'Cause', null, nil,0));

        LByteValue := PByte(LUDPPayLoad+LCurrentPos )^; 
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'IE Type:', LByteValue, @LByteValue,sizeOf(LByteValue)));
        Inc(LCurrentPos,SizeOf(LByteValue)); 

        LWordValue := PWord(LUDPPayLoad+LCurrentPos )^;
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'IE Length:', wpcapntohs( LWordValue ), @LWordValue,sizeOf(LWordValue)));
        Inc(LCurrentPos,SizeOf(LWordValue));    
        
        LByteValue := PByte(LUDPPayLoad+LCurrentPos )^;         
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'CR :', LByteValue shr 4, @LByteValue,sizeOf(LByteValue)));
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'Istance :', LByteValue shl 4, @LByteValue,sizeOf(LByteValue)));        
        Inc(LCurrentPos,SizeOf(LByteValue));    

        LByteValue := PByte(LUDPPayLoad+LCurrentPos )^; 
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'Cause:', LByteValue, @LByteValue,sizeOf(LByteValue)));
        Inc(LCurrentPos,SizeOf(LByteValue));         

        LByteValue := PByte(LUDPPayLoad+LCurrentPos )^; 
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'Spare bits:', LByteValue shr 3, @LByteValue,sizeOf(LByteValue)));
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'PCE (PDN Connection IE Error):', GetBitValue(LByteValue,6)=1, @LByteValue,sizeOf(LByteValue)));
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'BCE (Bear Context IE Error):', GetBitValue(LByteValue,7)=1, @LByteValue,sizeOf(LByteValue)));        
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'CS (Cause source):', GetBitValue(LByteValue,8), @LByteValue,sizeOf(LByteValue)));
        Inc(LCurrentPos,SizeOf(LByteValue));          
    end;

   
    Procedure AddRecovery;
    begin
        if LCurrentPos+5 <= LPayLoadLen then
        begin
          AListDetail.Add(AddHeaderInfo(aStartLevel+1,'Recovery', null, nil,0)); 
        
          LByteValue := PByte(LUDPPayLoad+LCurrentPos )^; 
          AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IE Type:', LByteValue, @LByteValue,sizeOf(LByteValue)));
          Inc(LCurrentPos,SizeOf(LByteValue)); 

          LWordValue := PWord(LUDPPayLoad+LCurrentPos )^;
          AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IE Length:', wpcapntohs( LWordValue ), @LWordValue,sizeOf(LWordValue)));
          Inc(LCurrentPos,SizeOf(LWordValue));    
        
          LByteValue := PByte(LUDPPayLoad+LCurrentPos )^;         
          AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'CR:', LByteValue shr 4, @LByteValue,sizeOf(LByteValue)));
          AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'Istance:', LByteValue shl 4, @LByteValue,sizeOf(LByteValue)));        
          Inc(LCurrentPos,SizeOf(LByteValue));        

          LByteValue := PByte(LUDPPayLoad+LCurrentPos )^; 
          AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'Restart counter:', LByteValue, @LByteValue,sizeOf(LByteValue)));
          Inc(LCurrentPos,SizeOf(LByteValue));  
        end;        
    end;

    Procedure AddEPSBear(aIndex:integer);
    begin
        AListDetail.Add(AddHeaderInfo(aIndex+1,'EPS bearer', null, nil,0));

        LByteValue := PByte(LUDPPayLoad+LCurrentPos )^; 
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'IE Type:', LByteValue, @LByteValue,sizeOf(LByteValue)));
        Inc(LCurrentPos,SizeOf(LByteValue)); 

        LWordValue := PWord(LUDPPayLoad+LCurrentPos )^;
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'IE Length:', wpcapntohs( LWordValue ), @LWordValue,sizeOf(LWordValue)));
        Inc(LCurrentPos,SizeOf(LWordValue));    
        
        LByteValue := PByte(LUDPPayLoad+LCurrentPos )^;         
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'CR:', LByteValue shr 4, @LByteValue,sizeOf(LByteValue)));
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'Istance:', LByteValue shl 4, @LByteValue,sizeOf(LByteValue)));        
        Inc(LCurrentPos,SizeOf(LByteValue));    

        LByteValue := PByte(LUDPPayLoad+LCurrentPos )^; 
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'Spare bits:', LByteValue shr 4, @LByteValue,sizeOf(LByteValue)));
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'EPS bear ID:', LByteValue shl 4, @LByteValue,sizeOf(LByteValue)));        
        Inc(LCurrentPos,SizeOf(LByteValue));               
    end;

    Procedure AddFully(aIndex:integer);
    begin
      AListDetail.Add(AddHeaderInfo(aIndex+1,'Fully Qualified Tunnel Endpoint Identifier (F-TEID)', null, nil,0));

      LByteValue := PByte(LUDPPayLoad+LCurrentPos )^; 
      AListDetail.Add(AddHeaderInfo(aIndex+2, 'IE Type:', LByteValue, @LByteValue,sizeOf(LByteValue)));
      Inc(LCurrentPos,SizeOf(LByteValue)); 

      LWordValue := PWord(LUDPPayLoad+LCurrentPos )^;
      AListDetail.Add(AddHeaderInfo(aIndex+2, 'IE Length:', wpcapntohs( LWordValue ), @LWordValue,sizeOf(LWordValue)));
      Inc(LCurrentPos,SizeOf(LWordValue));    
        
      LByteValue := PByte(LUDPPayLoad+LCurrentPos )^;         
      AListDetail.Add(AddHeaderInfo(aIndex+2, 'CR:', LByteValue shr 4, @LByteValue,sizeOf(LByteValue)));
      AListDetail.Add(AddHeaderInfo(aIndex+2, 'Istance:', LByteValue shl 4, @LByteValue,sizeOf(LByteValue)));        
      Inc(LCurrentPos,SizeOf(LByteValue));    

      LByteValue := PByte(LUDPPayLoad+LCurrentPos )^; 
      AListDetail.Add(AddHeaderInfo(aIndex+2, 'IPv4 present:', GetBitValue(LByteValue,1)=1, @LByteValue,sizeOf(LByteValue)));
      AListDetail.Add(AddHeaderInfo(aIndex+2, 'IPv6 present:', GetBitValue(LByteValue,1)=2, @LByteValue,sizeOf(LByteValue)));        
      AListDetail.Add(AddHeaderInfo(aIndex+2, 'Interface type:', LByteValue shr 2, @LByteValue,sizeOf(LByteValue)));           
      Inc(LCurrentPos,SizeOf(LByteValue));  

      LCardinalValue :=  PCardinal(LUDPPayLoad+LCurrentPos )^;
      AListDetail.Add(AddHeaderInfo(aIndex+2, 'TEID/GRE Key:', wpcapntohl( LCardinalValue ), @LCardinalValue,sizeOf(LCardinalValue)));             
      Inc(LCurrentPos,SizeOf(LCardinalValue));                   

      if GetBitValue(LByteValue,1)=1 then
      begin
        LCardinalValue :=  PCardinal(LUDPPayLoad+LCurrentPos )^;
        AListDetail.Add(AddHeaderInfo(aIndex+2, 'F-TEID IPv4:', intToIPV4( LCardinalValue ), @LCardinalValue,sizeOf(LCardinalValue)));          
        Inc(LCurrentPos,SizeOf(LCardinalValue));     
      end;
    end;    

    Procedure AddBear;
    begin
      AListDetail.Add(AddHeaderInfo(aStartLevel+1,'Bearer context', null, nil,0));

      LByteValue := PByte(LUDPPayLoad+LCurrentPos )^; 
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IE Type:', LByteValue, @LByteValue,sizeOf(LByteValue)));
      Inc(LCurrentPos,SizeOf(LByteValue)); 

      LWordValue := PWord(LUDPPayLoad+LCurrentPos )^;
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'IE Length:', wpcapntohs( LWordValue ), @LWordValue,sizeOf(LWordValue)));
      Inc(LCurrentPos,SizeOf(LWordValue));    
        
      LByteValue := PByte(LUDPPayLoad+LCurrentPos )^;         
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'CR:', LByteValue shr 4, @LByteValue,sizeOf(LByteValue)));
      AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'Istance:', LByteValue shl 4, @LByteValue,sizeOf(LByteValue)));        
      Inc(LCurrentPos,SizeOf(LByteValue));    

      AddEPSBear(aStartLevel+2);
      AddCause(aStartLevel+2);
      AddFully(aStartLevel+2);
    end;     
begin
  Result := False;

  if not HeaderUDP(aPacketData,aPacketSize,LPUDPHdr) then Exit;

  LUDPPayLoad  := GetUDPPayLoad(aPacketData,aPacketSize);
  LPayLoadLen  := UDPPayLoadLength(LPUDPHdr)-8;
  LMessageType := 0;
  LVersion     := ( PByte(LUDPPayLoad)^ shr 5);  
  
 AListDetail.Add(AddHeaderInfo(aStartLevel, Format('%s (%s)', [ProtoName, AcronymName]), null, nil,0));

  AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'Version:', LVersion, @LVersion,sizeOf(LVersion)));  
  case LVersion of
    1:
      begin      
        LGTPHeaderV1 := PTGTPHeaderV1(LUDPPayLoad);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'Flags:', ByteToBinaryString(LGTPHeaderV1.Flags), @LGTPHeaderV1.Flags,sizeOf(LGTPHeaderV1.Flags)));  
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'Protocol type:', ProtoTypeToString(GetBitValue(LGTPHeaderV1.Flags,4)), @LGTPHeaderV1.Flags,sizeOf(LGTPHeaderV1.Flags)));
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'Reserver:', GetBitValue(LGTPHeaderV1.Flags,5), @LGTPHeaderV1.Flags,sizeOf(LGTPHeaderV1.Flags)));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'Next extension header present:', GetBitValue(LGTPHeaderV1.Flags,6)=1, @LGTPHeaderV1.Flags,sizeOf(LGTPHeaderV1.Flags)));                        
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'Seq number present:', GetBitValue(LGTPHeaderV1.Flags,7)=1, @LGTPHeaderV1.Flags,sizeOf(LGTPHeaderV1.Flags)));                
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'N-PDU number present:', GetBitValue(LGTPHeaderV1.Flags,8)=1, @LGTPHeaderV1.Flags,sizeOf(LGTPHeaderV1.Flags)));                        
        LMessageType := LGTPHeaderV1.MessageType;
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'Type:', MessageTypeToString(LMessageType), @LMessageType,sizeOf(LMessageType)));
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'Length:', wpcapntohs( LGTPHeaderV1.MessageLen ), @LGTPHeaderV1.MessageLen,sizeOf(LGTPHeaderV1.MessageLen)));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'TEID:', wpcapntohl( LGTPHeaderV1.TEID ), @LGTPHeaderV1.TEID,sizeOf(LGTPHeaderV1.TEID)));  
         
        LCurrentPos := SizeOf(TGTPHeaderV1);      
        if GetBitValue(LGTPHeaderV1.Flags,7)=1 then      
        begin    
          LWordValue := PWord(LUDPPayLoad+LCurrentPos )^;
          AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'Sequence number:', wpcapntohs( LWordValue ), @LWordValue,sizeOf(LWordValue)));
          Inc(LCurrentPos,SizeOf(LWordValue))
        end;
          
       if GetBitValue(LGTPHeaderV1.Flags,8)=1 then
       begin
         { N-PDU number
           an (optional) 8-bit field. This field exists if any of the E, S, or PN bits are on. The field must be interpreted only if the PN bit is on.
         }
         Inc(LCurrentPos,SizeOf(Byte))
       end;

       if GetBitValue(LGTPHeaderV1.Flags,6)=1 then
       begin
          {
          Next extension header type
             an (optional) 8-bit field. This field exists if any of the E, S, or PN bits are on. The field must be interpreted only if the E bit is on.
             Next Extension Headers are as follows:
            Extension length
            an 8-bit field. This field states the length of this extension header, including the length, the contents, and the next extension header field, in 4-octet units, so the length of the extension must always be a multiple of 4.
            Contents
            extension header contents.
            Next extension header
            an 8-bit field. It states the type of the next extension, or 0 if no next extension exists. This permits chaining several next extension headers.
          }
       end;
       { Contents extension header contents.}
  
             
       
        
      
      end;
    2:
      begin 
        LGTPHeaderV2 := PTGTPHeaderV2(LUDPPayLoad);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'Flags:', ByteToBinaryString(LGTPHeaderV2.Flags), @LGTPHeaderV2.Flags,sizeOf(LGTPHeaderV2.Flags)));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'Piggybacking flag (P):', GetBitValue(LGTPHeaderV2.Flags,4)=1, @LGTPHeaderV2.Flags,sizeOf(LGTPHeaderV2.Flags)));
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'TEID flag (T):', GetBitValue(LGTPHeaderV2.Flags,5)=1, @LGTPHeaderV2.Flags,sizeOf(LGTPHeaderV2.Flags)));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, 'Message Priority(MP):', GetBitValue(LGTPHeaderV2.Flags,6)=1, @LGTPHeaderV2.Flags,sizeOf(LGTPHeaderV2.Flags)));                        
        LMessageType := LGTPHeaderV2.MessageType;
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'Type:', MessageTypeToString(LMessageType), @LMessageType,sizeOf(LMessageType)));
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'Length:', wpcapntohs( LGTPHeaderV2.MessageLen ), @LGTPHeaderV2.MessageLen,sizeOf(LGTPHeaderV2.MessageLen)));        

        LCurrentPos := SizeOf(TGTPHeaderV2);
        
        {32	TEID (only present if T=1)}
        {64 (32 if TEID not present)	Sequence number}    
        if GetBitValue(LGTPHeaderV2.Flags,5) = 1 then
        begin
          LCardinalValue :=  PCardinal(LUDPPayLoad+LCurrentPos )^;
          AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'TEID:', wpcapntohl( LCardinalValue ), @LCardinalValue,sizeOf(LCardinalValue)));             
          Inc(LCurrentPos,SizeOf(LCardinalValue));

          SetLength(LBytes,3); 
          Move((LUDPPayLoad+LCurrentPos )^,LBytes[0],3);
          AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'Sequence number:', wpcapntohl( BytesToInt32(LBytes) ), @LBytes,sizeOf(LBytes)));
          Inc(LCurrentPos,3);
        end
        else
        begin
          LIn64Value := PUint64(LUDPPayLoad+LCurrentPos )^;
          AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'Sequence number:', wpcapntohs( LIn64Value ), @LIn64Value,sizeOf(LIn64Value)));      
          Inc(LCurrentPos,SizeOf(LIn64Value));            
        end;
        
        LByteValue := PByte(LUDPPayLoad+LCurrentPos )^; 
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, 'Spare:', LByteValue, @LByteValue,sizeOf(LByteValue)));
        Inc(LCurrentPos,SizeOf(LByteValue)) ;
      end;
  else Exit;
  end;


  //KO use IE Type  REFACTORY !!!
  case LMessageType of
     GTP_CREATE_SESSION_REQUEST :
      begin

      end;
  

    GTP_CREATE_SESSION_RESPONSE:
      begin
        AddCause(aStartLevel);
        AddFully(aStartLevel);
        {PDN}        
        {APN}
        {PROTOCOL}        
        {BEAR}                
        {Fully}            
        {Private Ext or recovery}             
      end;

    GTP_MODIFY_BEARER_REQUEST:
      begin
        {idintication}  
        {Fully}
        {BEAR} 
        {recovery}
      end;

    GTP_MODIFY_BEARER_RESPONSE:
      begin
        AddCause(aStartLevel);
        AddBear;
        AddRecovery;  
      end;
    GTP_DELETE_SESSION_REQUEST:
      begin
        AddEPSBear(aStartLevel);
        {User location optional}
        {idintication} 
      end;  
      
    GTP_RELEASE_ACCESS_BEARERS_REQUEST  : 
      begin
      
      end;      
  
    GTP_DELETE_SESSION_RESPONSE,
    GTP_RELEASE_ACCESS_BEAR_RESPONSE:
      begin  
        AddCause(aStartLevel);         
        AddRecovery;  
      end;
  end;
 
  Result := True;
end;


class function TWPcapProtocolGTP.MessageTypeToString(aMsgType:Byte):String;
begin
 case aMsgType of  
   GTP_ECHO_REQUEST                              : Result := 'Echo Request';
   GTP_ECHO_RESPONSE                             : Result := 'Echo Response';
   GTP_ERROR_INDICATION                          : Result := 'Error Indication';
   GTP_RELEASE_ACCESS_BEARERS_REQUEST            : Result := 'Release Access Bearers Request';
   GTP_RELEASE_ACCESS_BEARERS_RESPONSE           : Result := 'Release Access Bearers Response';
   GTP_SUPPORTED_EXTENSION_HEADERS_NOTIFICATION  : Result := 'Supported Extension Headers Notification';
   GTP_CREATE_SESSION_REQUEST                    : Result := 'Create Session Request';
   GTP_CREATE_SESSION_RESPONSE                   : Result := 'Create Session Response';
   GTP_MODIFY_BEARER_REQUEST                     : Result := 'Modify Bearer Request';
   GTP_MODIFY_BEARER_RESPONSE                    : Result := 'Modify Bearer Response';
   GTP_DELETE_SESSION_REQUEST                    : Result := 'Delete Session Request';
   GTP_DELETE_SESSION_RESPONSE                   : Result := 'Delete Session Response';
   GTP_DELETE_BEARER_REQUEST                     : Result := 'Delete Bearer Request';
   GTP_DELETE_BEARER_RESPONSE                    : Result := 'Delete Bearer Response';
   GTP_CREATE_BEARER_REQUEST                     : Result := 'Create Bearer Request';
   GTP_CREATE_BEARER_RESPONSE                    : Result := 'Create Bearer Response';
   GTP_UPDATE_BEARER_REQUEST                     : Result := 'Update Bearer Request';
   GTP_UPDATE_BEARER_RESPONSE                    : Result := 'Update Bearer Response';
   GTP_RAN_INFORMATION_RELATIVE_CAPACITY         : Result := 'Ran Information Relative Capacity';
   GTP_CREATE_INDIRECT_DATA_FW_TUNNEL_REQUEST    : Result := 'Create Indirect Data Forwarding Tunnel Response';
   GTP_CREATE_INDIRECT_DATA_FW_TUNNEL_RESPONSE   : Result := 'Create Indirect Data Forwarding Tunnel Response';
   GTP_DELETE_INDIRECT_DATA_FW_TUNNEL_REQUEST    : Result := 'Delete Indirect Data Forwarding Tunnel Request';
   GTP_DELETE_INDIRECT_DATA_FW_TUNNEL_RESPONSE   : Result := 'Delete Indirect Data Forwarding Tunnel Response';
   GTP_RELEASE_ACCESS_BEAR_REQUEST               : Result := 'Release Access Bearers Request';
   GTP_RELEASE_ACCESS_BEAR_RESPONSE              : Result := 'Release Access Bearers Response';   
   GTP_END_USER_SERVICE_ACKNOWLEDGEMENT          : Result := 'End User Service Acknowledgement';
   GTP_END_USER_SERVICE_REJECT                   : Result := 'End User Service Reject';
   GTP_DATA_RECORD_TRANSFER                      : Result := 'Data Record Transfer';
   GTP_END_MARKER                                : Result := 'End Marker';
  else
      Result := 'Unknown';
  end;
  Result :=Format('%s [%d]',[Result,aMsgType]);

end;

class function TWPcapProtocolGTP.ProtoTypeToString(const aProtoType:Byte): String;
begin
  case aProtoType of
    1 : Result := 'GTP-U';
    2 : Result := 'GTP-C';
    3 : Result := 'GTP';
  else
      Result := 'Unknown';
  end;
  Result :=Format('%s [%d]',[Result,aProtoType]);      
end;



end.
                                                 
