unit wpcap.DB.SQLite.Packet;

interface

uses
  wpcap.DB.SQLite, wpcap.Protocol.UDP, wpcap.Protocol.TCP, wpcap.protocol, Math, wpcap.Conts,
  FireDAC.Comp.Client, System.Generics.Collections, wpcap.StrUtils,Vcl.Graphics,
  wpcap.Level.IP, wpcap.Types, FireDac.Stan.Param, wpcap.Level.Eth, wpcap.Packet,
  System.Classes, System.SysUtils, Data.Db,System.StrUtils,winApi.Winsock2,Wpcap.Protocol.RTP;

  type
    TWPcapDBSqLitePacket = Class(TWPcapDBSqLite)
  private
    FDQueryFlow     : TFDQuery;
    FDQuerySession  : TFDQuery;
  protected
    function GetSQLScriptDatabaseSchema: String;override;
    procedure InitConnection;override;
  public
    Destructor Destroy;override;
    ///<summary>
    /// Inserts a network packet into the database.
    ///</summary>
    ///<param name="aInternalPacket">
    /// A pointer to internal packet structure.
    ///</param>
    ///<remarks>
    /// This function inserts a network packet into the database. 
    /// The packet data is provided as a pointer and its length is specified.
    /// The date and time the packet was captured is also specified, 
    /// as well as various protocol information such as the Ethernet type, MAC addresses, link-layer and IP protocol, and source and destination IP and port information. 
    /// The function raises an EDatabaseError exception if an error occurs while inserting the packet.
    ///</remarks>
    ///<exception cref="EDatabaseError">
    /// An EDatabaseError exception is raised if an error occurs while inserting the packet.
    ///</exception>
    procedure InsertPacket(const aInternalPacket : PTInternalPacket);  
    
    /// <summary>
    /// Retrieves the packet data from the database at the specified packet number.
    /// </summary>
    /// <param name="aNPacket">The packet number to retrieve the data for.</param>
    /// <param name="aPacketSize">The size of the packet data.</param>
    /// <returns>A pointer to the packet data in memory.</returns>    
    function GetPacketDataFromDatabase(aNPacket: Integer;var aPacketSize:Integer): PByte;    
    
    /// <summary>
    /// Returns a list of string containing the hexadecimal dump of a packet data with
    /// line by line formatting.
    /// </summary>
    /// <param name="aNPacket">The number of packet to display (starting from 0)</param>
    /// <returns>A list of string containing the hexadecimal dump of the packet data</returns>
    function GetListHexPacket(aNPacket,aStartLevel: Integer;var aListDetail:TListHeaderString): TArray<String>;    

    Function GetFlowString(const aIpSrc,aIpDst:String;aPortSrc,aPortDst,aIPProto:Integer;aColorSrc,aColorDst:TColor):TStringList;
    function SaveRTPPayloadToFile(const aFilename, aIpSrc, aIpDst: String;aPortSrc, aPortDst: Integer;var aSoxCommand:String): Boolean;
    
  End;
implementation


function TWPcapDBSqLitePacket.GetSQLScriptDatabaseSchema: String;
{$REGION 'SQL Scrit'}
    CONST SQL_TABLE = 'CREATE TABLE PACKETS (                          '+sLineBreak+
                      '  NPACKET INTEGER PRIMARY KEY AUTOINCREMENT,    '+sLineBreak+ {Packet}
                      '  PACKET_LEN INTEGER,                           '+sLineBreak+
                      '  PACKET_DATE TEXT,                             '+sLineBreak+
                      '  ETH_TYPE INTEGER,                             '+sLineBreak+ {EThernet}
                      '  ETH_ACRONYM TEXT,                             '+sLineBreak+
                      '  MAC_SRC TEXT,                                 '+sLineBreak+
                      '  MAC_DST TEXT,                                 '+sLineBreak+
                      '  IS_IPV6 INTEGER,                              '+sLineBreak+                                                     
                      '  IPPROTO INTEGER,                              '+sLineBreak+ {IP Protocol} 
                      '  IPPROTO_STR TEXT,                             '+sLineBreak+                                            
                      '  PROTOCOL TEXT,                                '+sLineBreak+
                      '  PROTO_DETECT INTEGER,                         '+sLineBreak+         
                      '  IP_SRC TEXT,                                  '+sLineBreak+ {IP IpAddress}   
                      '  IP_DST TEXT,                                  '+sLineBreak+
                      '  PORT_SRC INTEGER,                             '+sLineBreak+ {TCP/UDP}  
                      '  PORT_DST NUMERIC,                             '+sLineBreak+
                      '  IANA_PROTO TEXT,                              '+sLineBreak+ {IANA}                         
                      '  SRC_ASN TEXT,                                 '+sLineBreak+ {GEOIP SRC}      
                      '  SRC_ORGANIZZATION TEXT,                       '+sLineBreak+       
                      '  SRC_LOCATION TEXT,                            '+sLineBreak+       
                      '  SRC_LATITUDE FLOAT,                           '+sLineBreak+       
                      '  SRC_LONGITUDE FLOAT,                          '+sLineBreak+                                                                                               
                      '  DST_ASN TEXT,                                 '+sLineBreak+ {GEOIP DST}        
                      '  DST_ORGANIZZATION TEXT,                       '+sLineBreak+       
                      '  DST_LOCATION TEXT,                           '+sLineBreak+       
                      '  DST_LATITUDE FLOAT,                           '+sLineBreak+       
                      '  DST_LONGITUDE FLOAT,                           '+sLineBreak+       
                      '  PACKET_DATA BLOB                              '+sLineBreak+
                      ');                                              ';
                      
           SQL_INDEX = 'CREATE UNIQUE INDEX PACKETS_NPACKET_IDX ON PACKETS (NPACKET);  ';

           SQL_VIEW  = 'CREATE VIEW VST_PACKETS AS                                                               ' +sLineBreak+ 
                       'SELECT                                                                                   ' +sLineBreak+ 
                       '  NPACKET, PACKET_LEN, PACKET_DATE,                                                      ' +sLineBreak+   {Packet}
                       '  ETH_TYPE, ETH_ACRONYM, MAC_SRC, MAC_DST, IS_IPV6,                                      ' +sLineBreak+   {EThernet}
                       '  PROTO_DETECT, IPPROTO, IPPROTO_STR, IFNULL(PROTOCOL,ETH_ACRONYM) AS PROTOCOL,          ' +sLineBreak+   {IP Protocol}                      
                       '  IFNULL(IP_SRC,MAC_SRC) AS IP_SRC, IFNULL(IP_DST,MAC_DST) AS IP_DST,                    ' +sLineBreak+   {IP IpAddress}   
                       '  PORT_SRC, PORT_DST,                                                                    ' +sLineBreak+   {TCP/UDP}   
                       '  IANA_PROTO,                                                                            ' +sLineBreak+   {IANA}   
                       '  SRC_ASN, SRC_ORGANIZZATION, SRC_LOCATION, SRC_LATITUDE, SRC_LONGITUDE,                 ' +sLineBreak+   {GEOIP SRC}
                       '  DST_ASN, DST_ORGANIZZATION, DST_LOCATION, DST_LATITUDE, DST_LONGITUDE                  ' +sLineBreak+   {GEOIP DST}   
                       '  FROM PACKETS;';
{$ENDREGION}
begin

  Result := SQL_TABLE +sLineBreak+
            SQL_INDEX +sLineBreak+
            SQL_VIEW;
end;

procedure TWPcapDBSqLitePacket.InitConnection;
{$REGION 'SQL insert}
CONST SQL_INSERT = 'INSERT INTO PACKETS(                                                                     ' +slineBreak+
                   '  PACKET_LEN, PACKET_DATE, PACKET_DATA,                                                  ' +sLineBreak+   {Packet}
                   '  ETH_TYPE, ETH_ACRONYM, MAC_SRC, MAC_DST, IS_IPV6,                                      ' +sLineBreak+   {EThernet}
                   '  PROTO_DETECT, IPPROTO, IPPROTO_STR, PROTOCOL,                                          ' +sLineBreak+   {IP Protocol}                      
                   '  IP_SRC,  IP_DST,                                                                       ' +sLineBreak+   {IP IpAddress}   
                   '  PORT_SRC, PORT_DST,                                                                    ' +sLineBreak+   {TCP/UDP}   
                   '  IANA_PROTO,                                                                            ' +sLineBreak+   {IANA}   
                   '  SRC_ASN, SRC_ORGANIZZATION, SRC_LOCATION, SRC_LATITUDE, SRC_LONGITUDE,                 ' +sLineBreak+   {GEOIP SRC}
                   '  DST_ASN, DST_ORGANIZZATION, DST_LOCATION, DST_LATITUDE, DST_LONGITUDE )                ' +sLineBreak+   {GEOIP DST}   
                   'VALUES                                                                                   ' +slineBreak+
                   ' (:pLen,:pDate,:pPacket,                                                                 ' +sLineBreak+   {Packet}
                   '  :pEthType,:pEthAcr,:pMacSrc,:pMacDst,:pIsIPV6,                                         ' +sLineBreak+   {EThernet}
                   '  :pProtoDetect,:pIpProto,:pIpProtoStr,:pProto,                                          ' +sLineBreak+   {IP Protocol} 
                   '  :pIpSrc,:pIpDst,                                                                       ' +sLineBreak+   {IP IpAddress}
                   '  :pPortSrc,:pPortDst,                                                                   ' +sLineBreak+   {TCP/UDP}   
                   '  :pProtoIANA,                                                                           ' +sLineBreak+   {IANA} 
                   '  :pSrcAsn,:pSrcOrg,:pSrcLoc,:pSrcLat,:pSrcLong,                                         ' +sLineBreak+   {GEOIP SRC}
                   '  :pDstAsn,:pDstOrg,:pDstLoc,:pDstLat,:pDstLong                                          ' +sLineBreak+   {GEOIP DST} 
                   ')';
{$ENDREGION}
begin
  inherited;
  { The default journal mode is WRITE-AHEAD LOGGING (WAL), which can improve 
    performance by reducing the amount of disk I/O required for write operations. }
//  Connection.Params.Add('JournalMode=WAL'); // Enable WAL mode   


  Connection.Params.Values['Synchronous'] := 'OFF'; 
  Connection.Params.Values['Cache']       := 'True'; 
  Connection.Params.Values['JournalMode'] := 'MEMORY';
  Connection.Params.Values['PageSize']    := '20480';
  Connection.FormatOptions.StrsEmpty2Null := True;

    
  FFDQueryTmp.SQL.Text                              := SQL_INSERT; 
  FFDQueryTmp.ParamByName('pLen').DataType          := ftInteger; {Packet}
  FFDQueryTmp.ParamByName('pDate').DataType         := ftString; 
  FFDQueryTmp.ParamByName('pEthType').DataType      := ftInteger; {EThernet} 
  FFDQueryTmp.ParamByName('pEthAcr').DataType       := ftString;
  FFDQueryTmp.ParamByName('pMacSrc').DataType       := ftString;
  FFDQueryTmp.ParamByName('pMacDst').DataType       := ftString;
  FFDQueryTmp.ParamByName('pIsIPV6').DataType       := ftInteger;      
  FFDQueryTmp.ParamByName('pProtoDetect').DataType  := ftInteger; {IP Protocol} 
  FFDQueryTmp.ParamByName('pProto').DataType        := ftString; 
  FFDQueryTmp.ParamByName('pIpProto').DataType      := ftInteger;
  FFDQueryTmp.ParamByName('pIpProtoStr').DataType   := ftString;
  FFDQueryTmp.ParamByName('pIpSrc').DataType        := ftString;  {IP IpAddress}
  FFDQueryTmp.ParamByName('pIpDst').DataType        := ftString;        
  FFDQueryTmp.ParamByName('pPortSrc').DataType      := ftInteger; {TCP/UDP}      
  FFDQueryTmp.ParamByName('pPortDst').DataType      := ftInteger;   
  FFDQueryTmp.ParamByName('pProtoIANA').DataType    := ftString;  {IANA}
  FFDQueryTmp.ParamByName('pSrcLoc').DataType       := ftString;  {GEOIP SRC} 
  FFDQueryTmp.ParamByName('pSrcOrg').DataType       := ftString;  
  FFDQueryTmp.ParamByName('pSrcAsn').DataType       := ftString;  
  FFDQueryTmp.ParamByName('pSrcLat').DataType       := ftFloat;   
  FFDQueryTmp.ParamByName('pSrcLong').DataType      := ftFloat;   
  FFDQueryTmp.ParamByName('pDstLoc').DataType       := ftString;  {GEOIP DST} 
  FFDQueryTmp.ParamByName('pDstOrg').DataType       := ftString;  
  FFDQueryTmp.ParamByName('pDstAsn').DataType       := ftString;
  FFDQueryTmp.ParamByName('pDstLat').DataType       := ftFloat;   
  FFDQueryTmp.ParamByName('pDstLong').DataType      := ftFloat;   
  FFDQueryTmp.ParamByName('pPacket').DataType       := ftBlob;    
  FFDQueryTmp.CachedUpdates                         := True;   
  FFDQueryGrid.SQL.Text                             := 'SELECT * FROM VST_PACKETS ORDER BY NPACKET ';
  FFDGetDataByID.SQL.Text                           := 'SELECT PACKET_DATA FROM PACKETS WHERE NPACKET = :pNPACKET '; 

  FDQueryFlow                                       := TFDQuery.Create(nil);
  FDQueryFlow.Connection                            := FConnection;
  FDQueryFlow.SQL.Text                              := 'SELECT IP_SRC,IP_DST,PORT_SRC,PORT_DST,PACKET_DATA FROM PACKETS                                                 '+sLineBreak+ 
                                                       'WHERE  ( ( IP_SRC = :pIpSrc AND IP_DST = :pIpDst ) OR (IP_SRC = :pIpDst AND IP_DST= :pIpSrc )  )                '+sLineBreak+ 
                                                       'AND    ( ( PORT_SRC = :pPortSrc AND PORT_DST = :pPortDst ) OR (PORT_SRC = :pPortDst AND PORT_DST= :pPortSrc )  ) '+sLineBreak+
                                                       'AND IPPROTO = :pIpProto ORDER BY PACKET_DATE ASC';

  FDQuerySession                                    := TFDQuery.Create(nil);
  FDQuerySession.Connection                         := FConnection;
  FDQuerySession.SQL.Text                           := 'SELECT IP_SRC,IP_DST,PORT_SRC,PORT_DST,PACKET_DATA FROM PACKETS                                                 '+sLineBreak+ 
                                                       'WHERE  ( ( IP_SRC = :pIpSrc AND IP_DST = :pIpDst ) )                '+sLineBreak+ 
                                                       'AND    ( ( PORT_SRC = :pPortSrc AND PORT_DST = :pPortDst )  ) '+sLineBreak+
                                                       'AND IPPROTO = :pIpProto ORDER BY PACKET_DATE ASC';                                                       
end; 

procedure TWPcapDBSqLitePacket.InsertPacket(const aInternalPacket : PTInternalPacket);
var LMemoryStream : TMemoryStream;
begin
  {TODO use Batch insert}
  if not FFDQueryTmp.Prepared then
    FFDQueryTmp.Prepare;
  {Packet}
  FFDQueryTmp.ParamByName('pLen').AsInteger         := aInternalPacket.PacketSize;
  FFDQueryTmp.ParamByName('pDate').AsString         := DateTimeToStr(aInternalPacket.PacketDate);
  {EThernet}
  FFDQueryTmp.ParamByName('pEthType').AsInteger     := aInternalPacket.Eth.EtherType;
  FFDQueryTmp.ParamByName('pEthAcr').AsString       := aInternalPacket.Eth.Acronym.Trim;
  FFDQueryTmp.ParamByName('pMacSrc').AsString       := ifthen(aInternalPacket.Eth.SrcAddr=SRC_MAC_RAW_DATA,String.Empty,aInternalPacket.Eth.SrcAddr);
  FFDQueryTmp.ParamByName('pMacDst').AsString       := ifthen(aInternalPacket.Eth.DestAddr=DST_MAC_RAW_DATA,String.Empty,aInternalPacket.Eth.DestAddr);
  FFDQueryTmp.ParamByName('pIsIPV6').AsInteger      := ifthen(aInternalPacket.IP.IsIPv6,1,0);  
  {IP Protocol} 
  FFDQueryTmp.ParamByName('pProtoDetect').AsInteger := aInternalPacket.IP.DetectedIPProto;  
  FFDQueryTmp.ParamByName('pIpProto').AsInteger     := aInternalPacket.IP.IpProto;    

  if aInternalPacket.IP.ProtoAcronym.Trim.IsEmpty then
    FFDQueryTmp.ParamByName('pProto').Clear
  else
    FFDQueryTmp.ParamByName('pProto').AsString := aInternalPacket.IP.ProtoAcronym;

  if aInternalPacket.IP.IpPrototr.Trim.IsEmpty then
    FFDQueryTmp.ParamByName('pIpProtoStr').Clear
  else
    FFDQueryTmp.ParamByName('pIpProtoStr').AsString := aInternalPacket.IP.IpPrototr;  
    
  if aInternalPacket.IP.Src.Trim.IsEmpty then
    FFDQueryTmp.ParamByName('pIpSrc').Clear
  else
    FFDQueryTmp.ParamByName('pIpSrc').AsString := aInternalPacket.IP.Src;  

  if aInternalPacket.IP.Dst.Trim.IsEmpty then
    FFDQueryTmp.ParamByName('pIpDst').Clear
  else
    FFDQueryTmp.ParamByName('pIpDst').AsString := aInternalPacket.IP.Dst;      
  
  {TCP/UDP}      
  if aInternalPacket.IP.PortSrc > 0 then  
    FFDQueryTmp.ParamByName('pPortSrc').AsInteger := aInternalPacket.IP.PortSrc
  else
    FFDQueryTmp.ParamByName('pPortSrc').Clear;

  if aInternalPacket.IP.PortDst > 0 then  
    FFDQueryTmp.ParamByName('pPortDst').AsInteger := aInternalPacket.IP.PortDst
  else
    FFDQueryTmp.ParamByName('pPortDst').Clear;
  
  {IANA} 
  FFDQueryTmp.ParamByName('pProtoIANA').AsString    := aInternalPacket.IP.IANAProtoStr;   
        
  {GEOIP SRC}
  FFDQueryTmp.ParamByName('pSrcLoc').AsString       := aInternalPacket.IP.SrcGeoIP.Location;
  FFDQueryTmp.ParamByName('pSrcOrg').AsString       := aInternalPacket.IP.SrcGeoIP.ASOrganization;  
  FFDQueryTmp.ParamByName('pSrcAsn').AsString       := aInternalPacket.IP.SrcGeoIP.ASNumber;    
  FFDQueryTmp.ParamByName('pSrcLat').AsFloat        := aInternalPacket.IP.SrcGeoIP.Latitude;
  FFDQueryTmp.ParamByName('pSrcLong').AsFloat       := aInternalPacket.IP.SrcGeoIP.Longitude;
  {GEOIP DST}
  FFDQueryTmp.ParamByName('pDstLoc').AsString       := aInternalPacket.IP.DestGeoIP.Location;
  FFDQueryTmp.ParamByName('pDstOrg').AsString       := aInternalPacket.IP.DestGeoIP.ASOrganization;  
  FFDQueryTmp.ParamByName('pDstAsn').AsString       := aInternalPacket.IP.DestGeoIP.ASNumber;    
  FFDQueryTmp.ParamByName('pDstLat').AsFloat        := aInternalPacket.IP.DestGeoIP.Latitude;
  FFDQueryTmp.ParamByName('pDstLong').AsFloat       := aInternalPacket.IP.DestGeoIP.Longitude;

  LMemoryStream := TMemoryStream.Create; 
  Try
    LMemoryStream.WriteBuffer(aInternalPacket.PacketData^,aInternalPacket.PacketSize);

    FFDQueryTmp.ParamByName('pPacket').LoadFromStream(LMemoryStream,ftBlob);
    FFDQueryTmp.ExecSQL;
  Finally
    FreeAndNil(LMemoryStream);
  End;  
end;

Function TWPcapDBSqLitePacket.GetPacketDataFromDatabase(aNPacket:Integer;var aPacketSize:Integer):PByte;
var LStream    : TMemoryStream;
begin
  Result      := nil;
  aPacketSize := 0;
  FFDGetDataByID.Close;
  FFDGetDataByID.ParamByName('pNPACKET').AsInteger := aNPacket; 
  FFDGetDataByID.Open;

  if not FFDGetDataByID.IsEmpty then
  begin
    LStream := TMemoryStream.Create;
    try  
      TBlobField(FFDGetDataByID.Fields[0]).SaveToStream(LStream);
      aPacketSize := LStream.Size;
      GetMem(Result, aPacketSize);
      LStream.Seek(0, soBeginning);
      LStream.ReadBuffer(Result^, aPacketSize);

      
    finally
      LStream.Free;
    end;    
  end;
  FFDGetDataByID.Close;  
end;

Function TWPcapDBSqLitePacket.GetListHexPacket(aNPacket,aStartLevel:Integer;var aListDetail:TListHeaderString):TArray<String>;
var LPacket           : PByte;
    LPacketSize       : Integer;
begin
  SetLength(Result,0);

  LPacket := GetPacketDataFromDatabase(aNPacket,LPacketSize);
  Try
    if Assigned(LPacket) then
    begin
      Result := DisplayHexData(LPacket,LPacketSize);
      TWpcapEthHeader.HeaderToString(LPacket,LPacketSize,aStartLevel,aListDetail);

    end;
  Finally
     FreeMem(LPacket);
  End;
end;

function TWPcapDBSqLitePacket.GetFlowString(const aIpSrc, aIpDst: String;aPortSrc, aPortDst,aIPProto: Integer; aColorSrc, aColorDst: TColor): TStringList;
CONST HTML_FORMAT = '<pre class="%s">%s</pre>';
var LPacketSize : Integer;
    LPacketData : PByte;
    LStream     : TMemoryStream;
    LPayLoad    : PByte;
    LCurrentIP  : String; 
    LTCPHdr     : PTCPHdr;
    LIsClient   : Boolean;
    LPayloadSize: Integer;
    LUDPHdr     : PUDPHdr;
begin
  Result      := TStringList.Create;
  FDQueryFlow.Close;
  FDQueryFlow.ParamByName('pIpSrc').AsString    := aIpSrc; 
  FDQueryFlow.ParamByName('pIpDst').AsString    := aIpDst; 
  FDQueryFlow.ParamByName('pPortSrc').AsInteger := aPortSrc; 
  FDQueryFlow.ParamByName('pPortDst').AsInteger := aPortDst;    
  FDQueryFlow.ParamByName('pIpProto').AsInteger := aIPProto;      
  FDQueryFlow.Open;
  
  LCurrentIP   := String.Empty;
  LIsClient    := False;
  
  if not FDQueryFlow.IsEmpty then
  begin
    LStream := TMemoryStream.Create;
    Try
      while not FDQueryFlow.eof do
      begin
        LStream.Seek(0, soBeginning);
        TBlobField(FDQueryFlow.FieldByName('PACKET_DATA')).SaveToStream(LStream);
        LPacketSize := LStream.Size;
        GetMem(LPacketData, LPacketSize);
        Try
          LStream.Seek(0, soBeginning);
          LStream.ReadBuffer(LPacketData^, LPacketSize);
          case aIPProto of
           IPPROTO_TCP :  
              begin
                if not TWPcapProtocolBaseTCP.HeaderTCP(LPacketData,LPacketSize,LTCPHdr) then exit;
                LPayLoad    := TWPcapProtocolBaseTCP.GetTCPPayLoad(LPacketData,LPacketSize);
                LPayloadSize := TWPcapProtocolBaseTCP.TCPPayLoadLength(LTCPHdr,LPacketData,LPacketSize)
              end;
           IPPROTO_UDP :
              begin
                if not TWPcapProtocolBaseUDP.HeaderUDP(LPacketData,LPacketSize,LUDPHdr) then exit;
                LPayLoad    := TWPcapProtocolBaseUDP.GetUDPPayLoad(LPacketData,LPacketSize);
                LPayloadSize := TWPcapProtocolBaseUDP.UDPPayLoadLength(LUDPHdr)            
              end
          else
            raise Exception.Create('Error invalid protocolo only TCP and UP protocol are supported');
          end;

          if LCurrentIP <> FDQueryFlow.FieldByName('IP_SRC').AsString then
          begin
            LCurrentIP := FDQueryFlow.FieldByName('IP_SRC').AsString;
            LIsClient  := not  LIsClient;
            
            if Result.Count > 0 then
              Result.Add(String.Empty)
            else
              Result.Add('<!DOCTYPE html>                                                                                                            ' +sLineBreak+
                         '         <head>                                                                                                            ' +sLineBreak+
                         '            <style>                                                                                                        ' +sLineBreak+
                         '                  pre{width: 100%; display:inline;font-family:Lucida console;white-space: pre-wrap;word-break: break-all;} ' +sLineBreak+
                         '                  pre.ServerStyle{background-color:#EDEDFB;color:#00007F;white-space: pre-wrap;}                           ' +sLineBreak+
                         '                  pre.ClientStyle{background-color:#FBEDED;color:#7F0000;white-space: pre-wrap;}                           ' +sLineBreak+
                         '            </style>                                                                                                       ' +sLineBreak+
                         '          </head>                                                                                                          ' +sLineBreak+
                         '         <html>                                                                                                            ' +sLineBreak+
                         ' <body style="background-color:#ffff"><pre>')

          end;
          Result.Add(Format(HTML_FORMAT,[ ifthen(LIsClient,'ClientStyle','ServerStyle'),
                                          BufferToASCII(LPayLoad,LPayloadSize)]));          
        Finally
          FreeMem(LPacketData)
        End;
        FDQueryFlow.Next;
      end;
    finally
      LStream.Free;
    end;    
  end;
  FDQueryFlow.Close;  
end;

function TWPcapDBSqLitePacket.SaveRTPPayloadToFile(const aFilename,aIpSrc, aIpDst: String;aPortSrc, aPortDst:Integer;var aSoxCommand:String): Boolean;
var LPacketSize : Integer;
    LPacketData : PByte;
    LStream     : TMemoryStream;
    LPayLoad    : PByte;
    LPayloadSize: Integer;
    LFileRaw    : TFileStream;
begin
  Result      := False;
  aSoxCommand := String.Empty;
  FDQuerySession.Close;
  FDQuerySession.ParamByName('pIpSrc').AsString    := aIpSrc; 
  FDQuerySession.ParamByName('pIpDst').AsString    := aIpDst; 
  FDQuerySession.ParamByName('pPortSrc').AsInteger := aPortSrc; 
  FDQuerySession.ParamByName('pPortDst').AsInteger := aPortDst;    
  FDQuerySession.ParamByName('pIpProto').AsInteger := IPPROTO_UDP;      
  FDQuerySession.Open;

  if not FDQuerySession.IsEmpty then
  begin
    LStream := TMemoryStream.Create;
    Try
      LFileRaw := TFileStream.Create(aFilename, fmCreate);
      Try
        while not FDQuerySession.eof do
        begin
          LStream.Seek(0, soBeginning);
          TBlobField(FDQuerySession.FieldByName('PACKET_DATA')).SaveToStream(LStream);
          LPacketSize := LStream.Size;
          GetMem(LPacketData, LPacketSize);
          Try
            LStream.Seek(0, soBeginning);
            LStream.ReadBuffer(LPacketData^, LPacketSize);

            LPayLoad    := TWPcapProtocolRTP.GetPayLoadRTP(LPacketData,LPacketSize,LPayloadSize); 
            if aSoxCommand.Trim.IsEmpty then            
              aSoxCommand :=  TWPcapProtocolRTP.GetSoxCommandDecode(LPacketData,LPacketSize);
            if (LPayLoad <> nil) and (LPayloadSize > 0) then
              LFileRaw.WriteBuffer(LPayLoad^, LPayloadSize);
        
          Finally
            FreeMem(LPacketData)
          End;
          FDQuerySession.Next;
        end;
        Result := True;
      Finally
        FreeAndNil(LFileRaw);
      End;
    finally
      LStream.Free;
    end;    
  end;
  FDQuerySession.Close;  
end;

destructor TWPcapDBSqLitePacket.Destroy;
begin
  FreeAndNil(FDQuerySession);
  FreeAndNil(FDQueryFlow);  
  inherited;
end;

end.
