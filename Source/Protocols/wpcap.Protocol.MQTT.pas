unit wpcap.Protocol.MQTT;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,idGlobal,
  Wpcap.protocol.TCP,System.Variants,Wpcap.BufferUtils,wpcap.StrUtils;

type

  {
  MQTT 3.1.1: https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
  MQTT 5.0: https://docs.oasis-open.org/mqtt/mqtt/v5.0/mqtt-v5.0.html
  }
  /// <summary>
  /// The MQTT protocol implementation class.
  /// </summary>
  TWPcapProtocolMQTT = Class(TWPcapProtocolBaseTCP)
  private
    CONST
    MQTT_RESERVED    = 0;   //No Extra info
    MQTT_CONNECT     = 1;   //OK
    MQTT_CONNACK     = 2;   //OK
    MQTT_PUBLISH     = 3;   //OK
    MQTT_PUBACK      = 4;
    MQTT_PUBREC      = 5;
    MQTT_PUBREL      = 6;
    MQTT_PUBCOMP     = 7;
    MQTT_SUBSCRIBE   = 8;   //OK
    MQTT_SUBACK      = 9;   //OK
    MQTT_UNSUBSCRIBE = 10;
    MQTT_UNSUBACK    = 11;
    MQTT_PINGREQ     = 12;  //No Extra info
    MQTT_PINGRESP    = 13;  //No Extra info
    MQTT_DISCONNECT  = 14;
    MQTT_RESERVED2   = 15;  //No Extra info
    class function MQTTMessageType(aType: Integer): string; static;
  protected
  public
    /// <summary>
    /// Returns the default MQTT port (110).
    /// </summary>
    class function DefaultPort: Word; override;
    /// <summary>
    /// Returns the ID number of the MQTT protocol.
    /// </summary>
    class function IDDetectProto: byte; override;
    /// <summary>
    /// Returns the name of the MQTT protocol.
    /// </summary>
    class function ProtoName: String; override;
    /// <summary>
    /// Returns the acronym name of the MQTT protocol.
    /// </summary>
    class function AcronymName: String; override;
    class function IsValid(const aPacket: PByte; aPacketSize: Integer;var aAcronymName: String; var aIdProtoDetected: Byte): Boolean; override;            
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean; override;
  end;


implementation

uses wpcap.Level.Ip;
{ TWPcapProtocolMQTT }
class function TWPcapProtocolMQTT.MQTTMessageType(aType: Integer): string;
begin
  case aType of
    MQTT_RESERVED   : Result := 'Reserved';
    MQTT_CONNECT    : Result := 'CONNECT';
    MQTT_CONNACK    : Result := 'CONNACK';
    MQTT_PUBLISH    : Result := 'PUBLISH';
    MQTT_PUBACK     : Result := 'PUBACK';
    MQTT_PUBREC     : Result := 'PUBREC';
    MQTT_PUBREL     : Result := 'PUBREL';
    MQTT_PUBCOMP    : Result := 'PUBCOMP';
    MQTT_SUBSCRIBE  : Result := 'SUBSCRIBE';
    MQTT_SUBACK     : Result := 'SUBACK';
    MQTT_UNSUBSCRIBE: Result := 'UNSUBSCRIBE';
    MQTT_UNSUBACK   : Result := 'UNSUBACK';
    MQTT_PINGREQ    : Result := 'PINGREQ';
    MQTT_PINGRESP   : Result := 'PINGRESP';
    MQTT_DISCONNECT : Result := 'DISCONNECT';
    MQTT_RESERVED2  : Result := 'Reserved';
  else Result := 'Unknown';
  end;
end;


class function TWPcapProtocolMQTT.DefaultPort: Word;
begin
  Result := PROTO_MQTT_PORT;
end;

class function TWPcapProtocolMQTT.IDDetectProto: byte;
begin
  Result := DETECT_PROTO_MQTT
end;

class function TWPcapProtocolMQTT.ProtoName: String;
begin
  Result := 'Message Queuing Telemetry Transport';
end;

class function TWPcapProtocolMQTT.AcronymName: String;
begin
  Result := 'MQTT';
end;

class function TWPcapProtocolMQTT.IsValid(const aPacket: PByte;aPacketSize: Integer; var aAcronymName: String;var aIdProtoDetected: Byte): Boolean;

var LTCPPtr: PTCPHdr;
begin
  Result := False;    
  if not HeaderTCP(aPacket,aPacketSize,LTCPPtr) then exit;   
  if not PayLoadLengthIsValid(LTCPPtr,aPacket,aPacketSize) then  Exit;

  Result := IsValidByDefaultPort(DstPort(LTCPPtr),SrcPort(LTCPPtr),aAcronymName,aIdProtoDetected);

  if not Result then
     Result := IsValidByPort(PROTO_MQTT_PORT_S,DstPort(LTCPPtr),SrcPort(LTCPPtr),aAcronymName,aIdProtoDetected)
end;

class function TWPcapProtocolMQTT.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean=False): Boolean;
var LTCPPayLoad        : PByte;
    LTCPPHdr           : PTCPHdr;
    LtmpByte           : Byte;
    LMsgType           : Byte; 
    LWordValue         : Word;
    LBytes             : TIdBytes; 
    LPos               : Integer;
    LTpcPayLoadLen     : Integer;
begin
  Result := False;

  if not HeaderTCP(aPacketData,aPacketSize,LTCPPHdr) then Exit;
  FIsFilterMode  := aIsFilterMode;
  LTCPPayLoad    := GetTCPPayLoad(aPacketData,aPacketSize);
  LTpcPayLoadLen := TCPPayLoadLength(LTCPPHdr,aPacketData,aPacketSize);
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, nil,LTpcPayLoadLen));

  LtmpByte  := PByte(LTCPPayLoad)^;

  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Flags',[AcronymName]), 'Flags:', ByteToBinaryString(LtmpByte), @LtmpByte,sizeOF(LtmpByte), LtmpByte )); 
  LMsgType := LtmpByte shr 4;
  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.MsgType',[AcronymName]), 'Message Type:',MQTTMessageType(LMsgType), @LMsgType,sizeOF(LMsgType), LMsgType)); 

  case LMsgType of
  
    MQTT_PUBLISH,
    MQTT_SUBSCRIBE:
     begin   
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.%s.Flags.DUP',[AcronymName,MQTTMessageType(LMsgType).ToLower]), 'DUP:', GetBitValue(LtmpByte,5)=1, @LtmpByte,sizeOF(LtmpByte))); 
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.%s.Flags.QoSLevel',[AcronymName,MQTTMessageType(LMsgType).ToLower]), 'QoS level:', LtmpByte shr 5, @LtmpByte,sizeOF(LtmpByte)));    
     end;
  end; 
  
  LtmpByte  := PByte(LTCPPayLoad+1)^;
  AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.MsgLen',[AcronymName]), 'Message len:',LtmpByte, @LtmpByte,sizeOF(LtmpByte)));   

  LPos := 2;  
  case LMsgType of
  
    MQTT_CONNECT:
      begin

        LWordValue := wpcapntohs( PWord(LTCPPayLoad+LPos)^ );
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Connect.ProtoNameLen',[AcronymName]), 'Protocol Name Length:', LWordValue, @LWordValue,sizeOF(LWordValue)));
        Inc(LPos,SizeOf(LWordValue));  
        
        SetLength(LBytes,LWordValue);
        Move((LTCPPayLoad + LPos)^, LBytes[0], LWordValue);      
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Connect.ProtoName',[AcronymName]), 'Protocol Name:',BytesToStringRaw(LBytes) , @LBytes,SizeOf(LBytes)));          
        inc(LPos,LWordValue);        


        LtmpByte := PByte(LTCPPayLoad + LPos)^;
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Connect.Version',[AcronymName]),  'Version:',LtmpByte, @LBytes,SizeOf(LBytes)));  
        Inc(LPos);
                     
        LtmpByte := PByte(LTCPPayLoad + LPos)^;
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Connect.Flags',[AcronymName]),  'Flags:',ByteToBinaryString(LtmpByte), @LtmpByte,sizeOF(LtmpByte),LtmpByte ));
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Connect.Flags.UserName',[AcronymName]),  'User name:',GetBitValue(LtmpByte,1)=1, @LtmpByte,sizeOF(LtmpByte)));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Connect.Flags.Password',[AcronymName]),  'Password:',GetBitValue(LtmpByte,2)=1, @LtmpByte,sizeOF(LtmpByte)));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Connect.Flags.WillRetain',[AcronymName]),  'Will retain:',GetBitValue(LtmpByte,3)=1, @LtmpByte,sizeOF(LtmpByte)));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Connect.Flags.QoSLevel',[AcronymName]) , 'QoS level:',GetBitValue(LtmpByte,4), @LtmpByte,sizeOF(LtmpByte)));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Connect.Flags.Will',[AcronymName]),  'Will:',LtmpByte shr 2 , @LtmpByte,sizeOF(LtmpByte)));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Connect.Flags.CleanSession',[AcronymName]),  'Clean session:',GetBitValue(LtmpByte,7)=1, @LtmpByte,sizeOF(LtmpByte)));        
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Connect.Flags.Reserved',[AcronymName]),  'Reserved:',GetBitValue(LtmpByte,8)=1, @LtmpByte,sizeOF(LtmpByte)));
        Inc(LPos);
        
        LWordValue := wpcapntohs(PWord(LTCPPayLoad + LPos)^);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Connect.KeepAlive',[AcronymName]), 'Keep alive:',LWordValue, @LWordValue,SizeOf(LWordValue)));    
        Inc(LPos,SizeOf(LWordValue));
        
        LWordValue := wpcapntohs( PWord(LTCPPayLoad+LPos)^ );        
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Connect.CliendIDLen',[AcronymName]), 'Client ID Length:', LWordValue, @LWordValue,sizeOF(LWordValue)));    
        Inc(LPos,SizeOf(LWordValue));
        
        SetLength(LBytes,LWordValue);
        Move((LTCPPayLoad + LPos)^, LBytes[0], LWordValue);      
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Connect.CliendID',[AcronymName]), 'Client ID:',BytesToStringRaw(LBytes) , @LBytes,SizeOf(LBytes)));      
                              
      end;

    MQTT_CONNACK:
      begin     

        LtmpByte := PByte(LTCPPayLoad + LPos)^;
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.ConnectACK.Reserved',[AcronymName]), 'Reserved:',LtmpByte=1, @LtmpByte,sizeOF(LtmpByte)));   
        Inc(LPos);
        
        LtmpByte := PByte(LTCPPayLoad + LPos)^; 
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.ConnectACK.ReturnCode',[AcronymName]), 'Return code:',LtmpByte, @LtmpByte,sizeOF(LtmpByte)));           
      end;

    MQTT_PUBLISH:
      begin  
        LWordValue := wpcapntohs(PWord(LTCPPayLoad + LPos)^);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Publish.Length',[AcronymName]), 'Topic Length:',LWordValue, @LWordValue,SizeOf(LWordValue)));    
        Inc(LPos,SizeOf(LWordValue));

        SetLength(LBytes,LWordValue);
        Move((LTCPPayLoad + LPos)^, LBytes[0], LWordValue);      
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Publish.Topic',[AcronymName]), 'Topic:',BytesToStringRaw(LBytes) , @LBytes,SizeOf(LBytes)));    
        Inc(LPos,LWordValue);        

              
        SetLength(LBytes,LTpcPayLoadLen- LPos);
        Move((LTCPPayLoad + LPos)^, LBytes[0],LTpcPayLoadLen- LPos );      
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Publish.Message',[AcronymName]), 'Message:',BytesToStringRaw(LBytes) , @LBytes,SizeOf(LBytes)));       
      end;
      
    MQTT_SUBSCRIBE  :
      begin
        LWordValue := wpcapntohs(PWord(LTCPPayLoad + LPos)^);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Subscribe.MessageIdentifier',[AcronymName]), 'Message Identifier:',LWordValue, @LWordValue,SizeOf(LWordValue)));    
        Inc(LPos,SizeOf(LWordValue));  

        LWordValue := wpcapntohs(PWord(LTCPPayLoad + LPos)^);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Subscribe.TopicLen',[AcronymName]), 'Topic Length:',LWordValue, @LWordValue,SizeOf(LWordValue)));    
        Inc(LPos,SizeOf(LWordValue));      

        SetLength(LBytes,LWordValue);
        Move((LTCPPayLoad + LPos)^, LBytes[0], LWordValue);      
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Subscribe.Topic',[AcronymName]), 'Topic:',BytesToStringRaw(LBytes) , @LBytes,SizeOf(LBytes)));    
        Inc(LPos,LWordValue);    

        LtmpByte := PByte(LTCPPayLoad + LPos)^;
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.Subscribe.RequestedQoS',[AcronymName]), 'Requested QoS:',LtmpByte, @LBytes,SizeOf(LBytes)));
        Inc(LPos);                          
      end;
      
    MQTT_SUBACK    :
      begin
        LWordValue := wpcapntohs(PWord(LTCPPayLoad + LPos)^);
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SubscribeACK.MessageIdentifier',[AcronymName]), 'Message Identifier:',LWordValue, @LWordValue,SizeOf(LWordValue)));    
        Inc(LPos,SizeOf(LWordValue));  

        LtmpByte := PByte(LTCPPayLoad + LPos)^;
        AListDetail.Add(AddHeaderInfo(aStartLevel+1, Format('%s.SubscribeACK.GrantedQoS',[AcronymName]), 'Granted QoS:',LtmpByte, @LBytes,SizeOf(LBytes)));  
        Inc(LPos);                          
      end;
    
  end;
  Result := True;
end;


end.
                                                 
