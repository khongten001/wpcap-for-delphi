unit wpcap.DB.SQLite.Packet;

interface

uses
  wpcap.DB.SQLite, wpcap.Protocol.UDP, wpcap.Protocol.TCP, wpcap.protocol, Math,
  System.Generics.Collections, wpcap.StrUtils, wpcap.Level.IP, wpcap.Types,FireDac.Stan.Param,
  wpcap.Level.Eth, wpcap.Packet,System.Classes,System.SysUtils,Data.Db;

  type
    TWPcapDBSqLitePacket = Class(TWPcapDBSqLite)
  private


  protected
    function GetSQLScriptDatabaseSchema: String;override;
    procedure InitConnection;override;
  public
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
    function GetListHexPacket(aNPacket: Integer;var aListDetail:TListHeaderString): TArray<String>;    
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
  FFDQueryGrid.SQL.Text                             := 'SELECT * FROM VST_PACKETS ORDER BY NPACKET ';
  FFDGetDataByID.SQL.Text                           := 'SELECT PACKET_DATA FROM PACKETS WHERE NPACKET = :pNPACKET ';    
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
  FFDQueryTmp.ParamByName('pMacSrc').AsString       := aInternalPacket.Eth.SrcAddr;
  FFDQueryTmp.ParamByName('pMacDst').AsString       := aInternalPacket.Eth.DestAddr;
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
  FFDGetDataByID.ParamByName('pNPACKET').AsInteger :=aNPacket; 
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

Function TWPcapDBSqLitePacket.GetListHexPacket(aNPacket:Integer;var aListDetail:TListHeaderString):TArray<String>;
var LPacket           : PByte;
    LPacketSize       : Integer;
    LInternalPacket   : PTInternalPacket;
    aUDPProtoDetected : TWPcapProtocolBaseUDP;	
    aTCPProtoDetected : TWPcapProtocolBaseTCP;	    
begin
  SetLength(Result,0);

  LPacket := GetPacketDataFromDatabase(aNPacket,LPacketSize);
  if Assigned(LPacket) then
  begin
    Result := DisplayHexData(LPacket,LPacketSize);
    TWpcapEthHeader.HeaderToString(LPacket,LPacketSize,aListDetail);
    if TWpcapIPHeader.HeaderToString(LPacket,LPacketSize,aListDetail) then
    begin
      New(LInternalPacket);
      Try
        TWpcapEthHeader.InternalPacket(LPacket,LPacketSize,nil,LInternalPacket);

        aUDPProtoDetected := FListProtolsUDPDetected.GetListByIDProtoDetected(LInternalPacket.IP.DetectedIPProto);
        if Assigned(aUDPProtoDetected) then
          aUDPProtoDetected.HeaderToString(LPacket,LPacketSize,AListDetail)
        else 
        begin
          aTCPProtoDetected := FListProtolsTCPDetected.GetListByIDProtoDetected(LInternalPacket.IP.DetectedIPProto);
          if Assigned(aTCPProtoDetected) then
            aTCPProtoDetected.HeaderToString(LPacket,LPacketSize,AListDetail)
        end;
      Finally
        Dispose(LInternalPacket);
      End;
    end;
  end;
end;




end.
