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

unit wpcap.Protocol.MQTT;

interface

uses
  wpcap.Protocol.Base, wpcap.Conts, wpcap.Types, System.SysUtils,idGlobal,wpcap.packet,
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
    class function HeaderToString(const aPacketData: PByte; aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean; override;
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

class function TWPcapProtocolMQTT.HeaderToString(const aPacketData: PByte;aPacketSize,aStartLevel: Integer; AListDetail: TListHeaderString;aIsFilterMode:Boolean;aAdditionalParameters: PTAdditionalParameters): Boolean;
var LTCPPayLoad    : PByte;
    LDummy         : Integer;
    LtmpByte       : Uint8;
    LMsgType       : Uint8; 
    LMsgTypeStr    : String;
    LTopicStr      : String;
    LWordValue     : Uint16;
    LPos           : Integer;
    LTpcPayLoadLen : Integer;
begin
  Result         := False;
  FIsFilterMode  := aIsFilterMode;
  LTCPPayLoad    := inherited GetPayLoad(aPacketData,aPacketSize,LTpcPayLoadLen,LDummy);

  if not Assigned(LTCPPayLoad) then
  begin
    FisMalformed := true;
    Exit;
  end;  
    
  AListDetail.Add(AddHeaderInfo(aStartLevel,AcronymName, Format('%s (%s)', [ProtoName, AcronymName]), null, LTCPPayLoad,LTpcPayLoadLen));
  LPos      := 0;
  LtmpByte  := ParserUint8Value(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,Format('%s.Flags',[AcronymName]), 'Flags:',AListDetail,ByteToBinaryStringInternal,True,LPos);

  LMsgType    := LtmpByte shr 4;
  LMsgTypeStr := MQTTMessageType(LMsgType);
  AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.Flags.MsgType',[AcronymName]), 'Message Type:',LMsgTypeStr, @LMsgType,sizeOF(LMsgType), LMsgType)); 

  case LMsgType of
  
    MQTT_PUBLISH,
    MQTT_SUBSCRIBE:
     begin   
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.%s.Flags.DUP',[AcronymName,MQTTMessageType(LMsgType).ToLower]), 'DUP:', GetBitValue(LtmpByte,5)=1, @LtmpByte,sizeOF(LtmpByte))); 
        AListDetail.Add(AddHeaderInfo(aStartLevel+2, Format('%s.%s.Flags.QoSLevel',[AcronymName,MQTTMessageType(LMsgType).ToLower]), 'QoS level:', LtmpByte shr 5, @LtmpByte,sizeOF(LtmpByte)));    
     end;
  end; 

  ParserUint8Value(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,Format('%s.MsgLen',[AcronymName]), 'Message len:',AListDetail,SizeaUint8ToStr,True,LPos);
 
  case LMsgType of
  
    MQTT_CONNECT:
      begin
        LWordValue := ParserUint16Value(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,Format('%s.Connect.ProtoNameLen',[AcronymName]), 'Protocol Name Length:',AListDetail,SizeWordToStr,True,LPos);
        ParserGenericBytesValue(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,LWordValue,Format('%s.Connect.ProtoName.Len',[AcronymName]), 'Protocol name length:',AListDetail,BytesToStringRawInternal,True,LPos);               
        ParserUint8Value(LTCPPayLoad,aStartLevel+2,LTpcPayLoadLen,Format('%s.Connect.Version',[AcronymName]), 'Version:',AListDetail,nil,True,LPos);
                     
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

        ParserUint16Value(aPacketData,aStartLevel+1,LTpcPayLoadLen,Format('%s.Connect.KeepAlive',[AcronymName]), 'Keep alive:',AListDetail,nil,True,LPos);
        
        LWordValue := ParserUint16Value(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,Format('%s.Connect.CliendID.Len',[AcronymName]), 'Client ID Length:',AListDetail,SizeWordToStr,True,LPos);
        ParserGenericBytesValue(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,LWordValue,Format('%s.Connect.CliendID',[AcronymName]), 'Client ID:',AListDetail,BytesToStringRawInternal,True,LPos);                                         
      end;

    MQTT_CONNACK:
      begin     
        ParserUint8Value(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,Format('%s.ConnectACK.Reserved',[AcronymName]), 'Reserved:',AListDetail,ByteToBooleanStr,True,LPos);        
        ParserUint8Value(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,Format('%s.ConnectACK.ReturnCode',[AcronymName]), 'Return code:',AListDetail,nil,True,LPos);        
      end;

    MQTT_PUBLISH:
      begin  
        LWordValue  := ParserUint16Value(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,Format('%s.Publish.Len',[AcronymName]), 'Topic Length:',AListDetail,SizeWordToStr,True,LPos);
        LTopicStr   := ParserGenericBytesValue(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,LWordValue,Format('%s.Publish.Topic',[AcronymName]), 'Topic:',AListDetail,BytesToStringRawInternal,True,LPos);                                                 
        LMsgTypeStr := Format('%s Topic publish %s',[LMsgTypeStr,LTopicStr]).Trim;
        if LTpcPayLoadLen- LPos > 0 then
          ParserGenericBytesValue(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,LTpcPayLoadLen- LPos,Format('%s.Publish.Message',[AcronymName]), 'Message:',AListDetail,BytesToStringRawInternal,True,LPos);    
      end;

    MQTT_SUBSCRIBE  :
      begin
        ParserUint16Value(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,Format('%s.Subscribe.MessageIdentifier',[AcronymName]), 'Message Identifier:',AListDetail,nil,True,LPos);
        LWordValue  := ParserUint16Value(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,Format('%s.Subscribe.Topic.Len',[AcronymName]), 'Topic Length:',AListDetail,SizeWordToStr,True,LPos);
        LTopicStr   := ParserGenericBytesValue(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,LWordValue,Format('%s.Subscribe.Topic',[AcronymName]), 'Topic:',AListDetail,BytesToStringRawInternal,True,LPos);                                                 
        LMsgTypeStr := Format('%s Topic subscribe %s',[LMsgTypeStr,LTopicStr]).Trim;
        ParserUint8Value(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,Format('%s.Subscribe.RequestedQoS',[AcronymName]), 'Requested QoS:',AListDetail,nil,True,LPos);        
      end;
      
    MQTT_SUBACK    :
      begin
        ParserUint16Value(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,Format('%s.SubscribeACK.MessageIdentifier',[AcronymName]), 'Message Identifier:',AListDetail,nil,True,LPos);
        ParserUint8Value(LTCPPayLoad,aStartLevel+1,LTpcPayLoadLen,Format('%s.SubscribeACK.GrantedQoS',[AcronymName]), 'Granted QoS:',AListDetail,nil,True,LPos);                                 
      end;
    
  end;

  aAdditionalParameters.Info := Format('%s %s',[aAdditionalParameters.Info,LMsgTypeStr]).Trim;
  Result := True;
end;


end.
                                                 
