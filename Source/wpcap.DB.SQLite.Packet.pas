unit wpcap.DB.SQLite.Packet;

interface

uses
  wpcap.DB.SQLite, wpcap.Protocol.UDP, wpcap.Protocol.TCP, wpcap.protocol, Math,
  wpcap.Conts, FireDAC.Comp.Client, System.Generics.Collections, wpcap.StrUtils,
  FireDAC.Stan.Option, Vcl.Graphics, wpcap.BufferUtils, wpcap.Level.IP,
  wpcap.Types, WinApi.Windows, FireDac.Stan.Param, wpcap.Level.Eth, wpcap.Packet,
  System.Classes, System.Variants, System.SysUtils, Data.Db, System.StrUtils,
  winApi.Winsock2, Wpcap.Protocol.RTP;

  type
    TWPcapDBSqLitePacket = Class(TWPcapDBSqLite)
  private
    FFDQueryFlow        : TFDQuery;
    FFDQueryInsert      : TFDQuery;
    FFDQuerySession     : TFDQuery;
    FFDQueryInsertLabel : TFDQuery;
    FFDQueryLabelList   : TFDQuery;
    FInsertToArchive    : SmallInt;
    FMaxInsertCache     : SmallInt;
    procedure SetMaxInsertCache(const Value: SmallInt);
    Function GetVarArrayByQuery(aQuery:TFdQuery;out aArray : Variant;out aDescription:String):Boolean;
  protected

    function GetSQLScriptDatabaseSchema: String;override;
    procedure InitConnection;override;
    procedure InsertMetadata(const aName: String; aValue: String);override;               
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
    procedure InsertLabelByLevel(const aListLabelByLevel: TListLabelByLevel);
    Function GetFlowString(const aIpSrc,aIpDst:String;aPortSrc,aPortDst,aIPProto:Integer;aColorSrc,aColorDst:TColor):TStringList;
    function SaveRTPPayloadToFile(const aFilename, aIpSrc, aIpDst: String;aPortSrc, aPortDst: Integer;var aSoxCommand:String): Boolean;
    procedure FlushArrayInsert;
    function GetFrameNumberByLabel(var aArrFrameNumber: variant; const aLabel: String;var aDescription:String): boolean;    
    procedure ResetCounterIntsert;
    {Property}
    property MaxInsertCache     : SmallInt  read FMaxInsertCache      write SetMaxInsertCache;
    property FDQueryLabelList  : TFDQuery  read FFDQueryLabelList    write FFDQueryLabelList;     
  End;
implementation


function TWPcapDBSqLitePacket.GetSQLScriptDatabaseSchema: String;
{$REGION 'SQL Scrit'}
    CONST SQL_TABLE = 'CREATE TABLE PACKETS (                          '+sLineBreak+
                      '  NPACKET INTEGER PRIMARY KEY AUTOINCREMENT,    '+sLineBreak+ {Packet}
                      '  PACKET_LEN INTEGER,                           '+sLineBreak+
                      '  PACKET_DATE TEXT,                             '+sLineBreak+
                      '  IS_MALFORMED INTEGER,                         '+sLineBreak+                        
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
                      '  PORT_DST INTEGER,                             '+sLineBreak+
                      '  IANA_PROTO TEXT,                              '+sLineBreak+ {IANA}                         
                      '  SRC_ASN TEXT,                                 '+sLineBreak+ {GEOIP SRC}      
                      '  SRC_ORGANIZZATION TEXT,                       '+sLineBreak+       
                      '  SRC_LOCATION TEXT,                            '+sLineBreak+
                      '  SRC_LATITUDE FLOAT,                           '+sLineBreak+       
                      '  SRC_LONGITUDE FLOAT,                          '+sLineBreak+                                                                                               
                      '  DST_ASN TEXT,                                 '+sLineBreak+ {GEOIP DST}        
                      '  DST_ORGANIZZATION TEXT,                       '+sLineBreak+       
                      '  DST_LOCATION TEXT,                            '+sLineBreak+       
                      '  DST_LATITUDE FLOAT,                           '+sLineBreak+       
                      '  DST_LONGITUDE FLOAT,                          '+sLineBreak+    
                      '  PACKET_RAW_TEXT TEXT,                         '+sLineBreak+  
                      '  XML_PACKET_DETAIL TEXT,                       '+sLineBreak+  
                      '  PACKET_DATA BLOB                              '+sLineBreak+
                      ');                                              ';

           SQL_DB_METADATA =  'CREATE TABLE %S(                     '+sLineBreak+
                              '  %S TEXT,                               '+sLineBreak+
                              '  %s TEXT                               '+sLineBreak+
                              ');';      

           SQL_DB_LABEL_FILTER =  'CREATE TABLE LABEL_FILTER(                         '+sLineBreak+
                                  '  ID_LABEL_NAME INTEGER , '+sLineBreak+ 
                                  '  LABEL_NAME TEXT,                                 '+sLineBreak+
                                  '  DESCRIPTION TEXT,                                '+sLineBreak+
                                  '  LEVEL INTEGER,                                   '+sLineBreak+ 
                                  '  ID_PARENT INTEGER                                '+sLineBreak+ 
                                  '); ';

           SQL_INDEX_LF_1 = 'CREATE UNIQUE INDEX LABEL_FILTER_IDX ON LABEL_FILTER (ID_LABEL_NAME);  ';
           SQL_INDEX_LF_2 = 'CREATE UNIQUE INDEX LABEL_FILTER_UQ ON LABEL_FILTER (LABEL_NAME,LEVEL);  ';
           
           SQL_INDEX = 'CREATE UNIQUE INDEX PACKETS_NPACKET_IDX ON PACKETS (NPACKET);  ';

           SQL_VIEW  = 'CREATE VIEW VST_PACKETS AS                                                               ' +sLineBreak+ 
                       'SELECT                                                                                   ' +sLineBreak+ 
                       '  NPACKET, PACKET_LEN, PACKET_DATE,PACKET_RAW_TEXT,XML_PACKET_DETAIL,IS_MALFORMED,       ' +sLineBreak+   {Packet}
                       '  ETH_TYPE, ETH_ACRONYM, MAC_SRC, MAC_DST, IS_IPV6,                                      ' +sLineBreak+   {EThernet}
                       '  PROTO_DETECT, IPPROTO, IPPROTO_STR, IFNULL(PROTOCOL,ETH_ACRONYM) AS PROTOCOL,          ' +sLineBreak+   {IP Protocol}                      
                       '  IFNULL(IP_SRC,MAC_SRC) AS IP_SRC, IFNULL(IP_DST,MAC_DST) AS IP_DST,                    ' +sLineBreak+   {IP IpAddress}   
                       '  PORT_SRC, PORT_DST ,                                                                   ' +sLineBreak+   {TCP/UDP}   
                       '  IANA_PROTO,                                                                            ' +sLineBreak+   {IANA}   
                       '  SRC_ASN, SRC_ORGANIZZATION, SRC_LOCATION, SRC_LATITUDE, SRC_LONGITUDE,                 ' +sLineBreak+   {GEOIP SRC}
                       '  DST_ASN, DST_ORGANIZZATION, DST_LOCATION, DST_LATITUDE, DST_LONGITUDE                  ' +sLineBreak+   {GEOIP DST}   
                       '  FROM PACKETS;';
{$ENDREGION}
begin

  Result := SQL_TABLE            +sLineBreak+
            SQL_INDEX            +sLineBreak+
            SQL_VIEW             +sLineBreak+
            SQL_DB_LABEL_FILTER  +sLineBreak+
            SQL_INDEX_LF_1       +sLineBreak+
            SQL_INDEX_LF_2       +sLineBreak+
            Format(SQL_DB_METADATA,[GetMetadataTableName,GetMetadataCOLUMN_NAME_NAME,GetMetadataCOLUMN_NAME_VALUE]);
end;

procedure TWPcapDBSqLitePacket.InitConnection;
{$REGION 'SQL insert}
CONST SQL_INSERT = 'INSERT INTO PACKETS(                                                                     ' +slineBreak+
                   '  PACKET_LEN, PACKET_DATE, PACKET_DATA,PACKET_RAW_TEXT,XML_PACKET_DETAIL, IS_MALFORMED,  ' +sLineBreak+   {Packet}
                   '  ETH_TYPE, ETH_ACRONYM, MAC_SRC, MAC_DST, IS_IPV6,                                      ' +sLineBreak+   {EThernet}
                   '  PROTO_DETECT, IPPROTO, IPPROTO_STR, PROTOCOL,                                          ' +sLineBreak+   {IP Protocol}                      
                   '  IP_SRC,  IP_DST,                                                                       ' +sLineBreak+   {IP IpAddress}   
                   '  PORT_SRC, PORT_DST,                                                                    ' +sLineBreak+   {TCP/UDP}   
                   '  IANA_PROTO,                                                                            ' +sLineBreak+   {IANA}   
                   '  SRC_ASN, SRC_ORGANIZZATION, SRC_LOCATION, SRC_LATITUDE, SRC_LONGITUDE,                 ' +sLineBreak+   {GEOIP SRC}
                   '  DST_ASN, DST_ORGANIZZATION, DST_LOCATION, DST_LATITUDE, DST_LONGITUDE )                ' +sLineBreak+   {GEOIP DST}   
                   'VALUES                                                                                   ' +slineBreak+
                   ' (:pLen,:pDate,:pPacket,:pPacketRaw,:pXMLInfo,:pIsMalformed ,                            ' +sLineBreak+   {Packet}
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


  Connection.Params.Values['Synchronous']                   := 'OFF'; 
  Connection.Params.Values['Cache']                         := 'True'; 
  Connection.Params.Values['JournalMode']                   := 'MEMORY';
  Connection.Params.Values['PageSize']                      := '20480';
  Connection.FormatOptions.StrsEmpty2Null                   := True;

  FFDQueryInsert                                            := TFDQuery.Create(nil);
  FFDQueryInsert.Connection                                 := FConnection;    
  FFDQueryInsert.SQL.Text                                   := SQL_INSERT; 
  FFDQueryInsert.ParamByName('pLen').DataType               := ftInteger; {Packet}
  FFDQueryInsert.ParamByName('pDate').DataType              := ftString; 
  FFDQueryInsert.ParamByName('pIsMalformed').DataType       := ftInteger; 
  FFDQueryInsert.ParamByName('pEthType').DataType           := ftInteger; {EThernet} 
  FFDQueryInsert.ParamByName('pEthAcr').DataType            := ftString;
  FFDQueryInsert.ParamByName('pMacSrc').DataType            := ftString;
  FFDQueryInsert.ParamByName('pMacDst').DataType            := ftString;
  FFDQueryInsert.ParamByName('pIsIPV6').DataType            := ftInteger;      
  FFDQueryInsert.ParamByName('pProtoDetect').DataType       := ftInteger; {IP Protocol} 
  FFDQueryInsert.ParamByName('pProto').DataType             := ftString; 
  FFDQueryInsert.ParamByName('pIpProto').DataType           := ftInteger;
  FFDQueryInsert.ParamByName('pIpProtoStr').DataType        := ftString;
  FFDQueryInsert.ParamByName('pIpSrc').DataType             := ftString;  {IP IpAddress}
  FFDQueryInsert.ParamByName('pIpDst').DataType             := ftString;        
  FFDQueryInsert.ParamByName('pPortSrc').DataType           := ftInteger; {TCP/UDP}      
  FFDQueryInsert.ParamByName('pPortDst').DataType           := ftInteger;   
  FFDQueryInsert.ParamByName('pProtoIANA').DataType         := ftString;  {IANA}
  FFDQueryInsert.ParamByName('pSrcLoc').DataType            := ftString;  {GEOIP SRC} 
  FFDQueryInsert.ParamByName('pSrcOrg').DataType            := ftString;  
  FFDQueryInsert.ParamByName('pSrcAsn').DataType            := ftString;  
  FFDQueryInsert.ParamByName('pSrcLat').DataType            := ftFloat;   
  FFDQueryInsert.ParamByName('pSrcLong').DataType           := ftFloat;   
  FFDQueryInsert.ParamByName('pDstLoc').DataType            := ftString;  {GEOIP DST} 
  FFDQueryInsert.ParamByName('pDstOrg').DataType            := ftString;  
  FFDQueryInsert.ParamByName('pDstAsn').DataType            := ftString;
  FFDQueryInsert.ParamByName('pXMLInfo').DataType           := ftString;  
  FFDQueryInsert.ParamByName('pPacketRaw').DataType         := ftString;    
  FFDQueryInsert.ParamByName('pDstLat').DataType            := ftFloat;   
  FFDQueryInsert.ParamByName('pDstLong').DataType           := ftFloat;
  FFDQueryInsert.ParamByName('pPacket').DataType            := ftBlob;    
  FFDQueryInsert.CachedUpdates                              := True;   
  FFDQueryGrid.SQL.Text                                     := 
                                                                 'SELECT                                                                                 ' +sLineBreak+ 
                                                               '  NPACKET, PACKET_LEN, PACKET_DATE,IS_MALFORMED,                                                      ' +sLineBreak+ 
                                                               '  ETH_TYPE, ETH_ACRONYM, MAC_SRC, MAC_DST, IS_IPV6,                                      ' +sLineBreak+   {EThernet}
                                                               '  PROTO_DETECT, IPPROTO, IPPROTO_STR, IFNULL(PROTOCOL,ETH_ACRONYM) AS PROTOCOL,          ' +sLineBreak+   {IP Protocol}                      
                                                               '  IFNULL(IP_SRC,MAC_SRC) AS IP_SRC, IFNULL(IP_DST,MAC_DST) AS IP_DST,                    ' +sLineBreak+   {IP IpAddress}   
                                                               '  PORT_SRC, PORT_DST,                                                                    ' +sLineBreak+   {TCP/UDP}   
                                                               '  IANA_PROTO,                                                                            ' +sLineBreak+   {IANA}   
                                                               '  SRC_ASN, SRC_ORGANIZZATION, SRC_LOCATION, SRC_LATITUDE, SRC_LONGITUDE,                 ' +sLineBreak+   {GEOIP SRC}
                                                               '  DST_ASN, DST_ORGANIZZATION, DST_LOCATION, DST_LATITUDE, DST_LONGITUDE                  ' +sLineBreak+   {GEOIP DST} 
                                                               '  FROM VST_PACKETS ORDER BY NPACKET ';            
  FFDGetDataByID.SQL.Text                                   := 'SELECT PACKET_DATA FROM PACKETS WHERE NPACKET = :pNPACKET '; 

  FFDQueryFlow                                              := TFDQuery.Create(nil);
  FFDQueryFlow.Connection                                   := FConnection;
  FFDQueryFlow.SQL.Text                                     := 'SELECT IP_SRC,IP_DST,PORT_SRC,PORT_DST,PACKET_DATA FROM PACKETS                                                  '+sLineBreak+ 
                                                               'WHERE  ( ( IP_SRC = :pIpSrc AND IP_DST = :pIpDst ) OR (IP_SRC = :pIpDst AND IP_DST= :pIpSrc )  )                 '+sLineBreak+ 
                                                               'AND    ( ( PORT_SRC = :pPortSrc AND PORT_DST = :pPortDst ) OR (PORT_SRC = :pPortDst AND PORT_DST= :pPortSrc )  ) '+sLineBreak+
                                                               'AND IPPROTO = :pIpProto ORDER BY PACKET_DATE ASC';

  FFDQuerySession                                            := TFDQuery.Create(nil);
  FFDQuerySession.Connection                                 := FConnection;
  FFDQuerySession.SQL.Text                                   := 'SELECT IP_SRC,IP_DST,PORT_SRC,PORT_DST,PACKET_DATA FROM PACKETS   '+sLineBreak+ 
                                                               'WHERE  ( ( IP_SRC = :pIpSrc AND IP_DST = :pIpDst ) )              '+sLineBreak+ 
                                                               'AND    ( ( PORT_SRC = :pPortSrc AND PORT_DST = :pPortDst )  )     '+sLineBreak+
                                                               'AND IPPROTO = :pIpProto ORDER BY PACKET_DATE ASC';     

  FFDQueryInsertLabel                                        := TFDQuery.Create(nil);
  FFDQueryInsertLabel.Connection                             := FConnection;
  FFDQueryInsertLabel.SQL.Text                               := 'INSERT INTO LABEL_FILTER (ID_LABEL_NAME,LABEL_NAME,DESCRIPTION,LEVEL,ID_PARENT) VALUES (:pIdLabel,:pLabelName,:pDescription,:pLevel,:pIdParent)';
  FFDQueryInsertLabel.ParamByName('pIdLabel').DataType       := ftInteger; 
  FFDQueryInsertLabel.ParamByName('pLabelName').DataType     := ftString;
  FFDQueryInsertLabel.ParamByName('pDescription').DataType   := ftString;
  FFDQueryInsertLabel.ParamByName('pLevel').DataType         := ftInteger; 
  FFDQueryInsertLabel.ParamByName('pIdParent').DataType      := ftInteger;    
  FMaxInsertCache                                            := 2000; 

  FFDQueryLabelList                                          := TFDQuery.Create(nil);
  FFDQueryLabelList.Connection                               := FConnection;
  FFDQueryLabelList.SQL.Text                                 := 'SELECT * FROM LABEL_FILTER';
end; 


Function TWPcapDBSqLitePacket.GetVarArrayByQuery(aQuery:TFdQuery;out aArray : Variant;out aDescription:String):Boolean;
var I               : integer;
    StringBuilder   : TStringBuilder;
begin
  Result        := False;
  Try
    if not aQuery.Active then
      aQuery.Open;

    if aQuery.isEmpty then exit;
    StringBuilder := TStringBuilder.Create;
    Try
      aArray  := VarArrayCreate([0, aQuery.RecordCount-1], varVariant);

      I := 0;
      while Not aQuery.Eof do
      begin
        if I = 0 then
          StringBuilder.Append(aQuery.Fields[0].AsString)
        else
          StringBuilder.AppendFormat(',%s',[aQuery.Fields[0].AsString]);
           
        aArray[I] := aQuery.Fields[0].Value;
        Inc(I);
        aQuery.Next;
        if not aQuery.Eof then
        begin
          {nell'eventualità che la query non è in fetchall ridiminesione l'array (perdita di performance)}
          if I = aQuery.RecordCount then
            VarArrayRedim(aArray, aQuery.RecordCount-1);
        end;
      end;

      aDescription := StringBuilder.ToString;  
      Result       := True;
    Finally
      FreeAndNil(StringBuilder);
    End;
  Finally
    aQuery.Close;
  End;
end;


function TWPcapDBSqLitePacket.GetFrameNumberByLabel(var aArrFrameNumber:variant; const aLabel : String;var aDescription:String):boolean;
CONST QRY_FILTER_SPEAKER = 'SELECT NPACKET FROM PACKETS ' +
                           'WHERE XML_PACKET_DETAIL Like :pLabel';
var lQuery      : TFdQuery;
begin
  lQuery := TFdQuery.Create(nil);
  try
    lQuery.Connection                          := FConnection;
    lQuery.SQL.Text                            := QRY_FILTER_SPEAKER;
    lQuery.FetchOptions.Mode                   := fmAll;
    lQuery.ParamByName('pLabel').AsString      := '%'+aLabel+'%';
    lQuery.Open;
    result := GetVarArrayByQuery(lQuery,aArrFrameNumber,aDescription); 
  finally
    FreeAndNil(lQuery)
  end;
end;   

procedure TWPcapDBSqLitePacket.InsertLabelByLevel(const aListLabelByLevel : TListLabelByLevel);
var Literator : TDictionary<String, TLabelByLevel>.TPairEnumerator;

    procedure AddLabelFilter(const aIdParent,aLevel: Integer;var AIndex:Integer);
    var aParent : Integer;
    begin
      aParent := AIndex;  
      Inc(AIndex);
      if Literator.Current.Value.LabelName.Trim.IsEmpty then exit;

      FFDQueryInsertLabel.ParamByName('pIdLabel').AsIntegers[AIndex]     := AIndex;
      FFDQueryInsertLabel.ParamByName('pLabelName').AsStrings[AIndex]    := Literator.Current.Value.LabelName;
      FFDQueryInsertLabel.ParamByName('pDescription').AsStrings[AIndex]  := Literator.Current.Value.Description;
      FFDQueryInsertLabel.ParamByName('pLevel').AsIntegers[AIndex]       := aLevel;

      if aIdParent > 0 then
        FFDQueryInsertLabel.ParamByName('pIdParent').AsIntegers[AIndex] := aIdParent
      else
        FFDQueryInsertLabel.ParamByName('pIdParent').Clear;

      Literator.MoveNext;
      while AIndex < aListLabelByLevel.Count -1 do
      begin

        if Literator.Current.Value.Level = 0 then Break;        
        if Literator.Current.Value.Level <= aLevel then Break;      
        
        AddLabelFilter(aParent,Literator.Current.Value.Level,AIndex);     
      end;
   
    end;  
var I : integer;   
   
begin
  if aListLabelByLevel.Count = 0 then Exit;

  if not FFDQueryInsertLabel.Prepared then
    FFDQueryInsertLabel.Prepare;
  FFDQueryInsertLabel.Params.ArraySize := aListLabelByLevel.Count;
  Literator := aListLabelByLevel.GetEnumerator();  

  
  // Popolare i parametri per ogni riga nella batch
  i := 0;
  Literator.MoveNext;
  while I < aListLabelByLevel.Count -1 do
    AddLabelFilter(0,Literator.Current.Value.Level,I); 
  Try    
    FFDQueryInsertLabel.Execute(FFDQueryInsertLabel.Params.ArraySize); // esegue la batch insert        
  except 
  end;
end;


procedure TWPcapDBSqLitePacket.FlushArrayInsert;
begin
  if FInsertToArchive > -1 then
    FFDQueryInsert.Execute(FInsertToArchive);
  ResetCounterIntsert;
end;


procedure TWPcapDBSqLitePacket.InsertPacket(const aInternalPacket : PTInternalPacket);
var LMemoryStream : TMemoryStream;

begin
  {TODO use Batch insert}
  if not FFDQueryInsert.Prepared then
  begin
    FFDQueryInsert.Prepare;
    FFDQueryInsert.Params.ArraySize := FMaxInsertCache;    
  end;

  Inc(FInsertToArchive);

  if FInsertToArchive > FMaxInsertCache -1 then
  begin
    FlushArrayInsert;
    Inc(FInsertToArchive);
  end;
  {Packet}
  FFDQueryInsert.ParamByName('pLen').AsIntegers[FInsertToArchive]         := aInternalPacket.PacketSize;
  FFDQueryInsert.ParamByName('pDate').AsStrings[FInsertToArchive]         := DateTimeToStr(aInternalPacket.PacketDate);  
  FFDQueryInsert.ParamByName('pIsMalformed').AsIntegers[FInsertToArchive] := ifthen(aInternalPacket.IsMalformed,1,0); 
  {EThernet}
  FFDQueryInsert.ParamByName('pEthType').AsIntegers[FInsertToArchive]     := aInternalPacket.Eth.EtherType;
  FFDQueryInsert.ParamByName('pEthAcr').AsStrings[FInsertToArchive]       := aInternalPacket.Eth.Acronym.Trim;
  FFDQueryInsert.ParamByName('pMacSrc').AsStrings[FInsertToArchive]       := ifthen(aInternalPacket.Eth.SrcAddr=SRC_MAC_RAW_DATA,String.Empty,aInternalPacket.Eth.SrcAddr);
  FFDQueryInsert.ParamByName('pMacDst').AsStrings[FInsertToArchive]       := ifthen(aInternalPacket.Eth.DestAddr=DST_MAC_RAW_DATA,String.Empty,aInternalPacket.Eth.DestAddr);
  FFDQueryInsert.ParamByName('pIsIPV6').AsIntegers[FInsertToArchive]      := ifthen(aInternalPacket.IP.IsIPv6,1,0);  
  {IP Protocol} 
  FFDQueryInsert.ParamByName('pProtoDetect').AsIntegers[FInsertToArchive] := aInternalPacket.IP.DetectedIPProto;  
  FFDQueryInsert.ParamByName('pIpProto').AsIntegers[FInsertToArchive]     := aInternalPacket.IP.IpProto;    

  if aInternalPacket.IP.ProtoAcronym.Trim.IsEmpty then
    FFDQueryInsert.ParamByName('pProto').Clear(FInsertToArchive)
  else
    FFDQueryInsert.ParamByName('pProto').AsStrings[FInsertToArchive] := aInternalPacket.IP.ProtoAcronym;

  if aInternalPacket.IP.IpPrototr.Trim.IsEmpty then
    FFDQueryInsert.ParamByName('pIpProtoStr').Clear(FInsertToArchive)
  else
    FFDQueryInsert.ParamByName('pIpProtoStr').AsStrings[FInsertToArchive] := aInternalPacket.IP.IpPrototr;  
    
  if aInternalPacket.IP.Src.Trim.IsEmpty then
    FFDQueryInsert.ParamByName('pIpSrc').Clear(FInsertToArchive)
  else
    FFDQueryInsert.ParamByName('pIpSrc').AsStrings[FInsertToArchive] := aInternalPacket.IP.Src;  

  if aInternalPacket.IP.Dst.Trim.IsEmpty then
    FFDQueryInsert.ParamByName('pIpDst').Clear(FInsertToArchive)
  else
    FFDQueryInsert.ParamByName('pIpDst').AsStrings[FInsertToArchive] := aInternalPacket.IP.Dst;      
  
  {TCP/UDP}      
  if aInternalPacket.IP.PortSrc > 0 then  
    FFDQueryInsert.ParamByName('pPortSrc').AsIntegers[FInsertToArchive] := aInternalPacket.IP.PortSrc
  else
    FFDQueryInsert.ParamByName('pPortSrc').Clear(FInsertToArchive);

  if aInternalPacket.IP.PortDst > 0 then  
    FFDQueryInsert.ParamByName('pPortDst').AsIntegers[FInsertToArchive] := aInternalPacket.IP.PortDst
  else
    FFDQueryInsert.ParamByName('pPortDst').Clear(FInsertToArchive);
  
  {IANA} 
  FFDQueryInsert.ParamByName('pProtoIANA').AsStrings[FInsertToArchive]     := aInternalPacket.IP.IANAProtoStr;   
        
  {GEOIP SRC}
  FFDQueryInsert.ParamByName('pSrcLoc').AsStrings[FInsertToArchive]        := aInternalPacket.IP.SrcGeoIP.Location;
  FFDQueryInsert.ParamByName('pSrcOrg').AsStrings[FInsertToArchive]        := aInternalPacket.IP.SrcGeoIP.ASOrganization;  
  FFDQueryInsert.ParamByName('pSrcAsn').AsStrings[FInsertToArchive]        := aInternalPacket.IP.SrcGeoIP.ASNumber;    
  FFDQueryInsert.ParamByName('pSrcLat').AsFloats[FInsertToArchive]         := aInternalPacket.IP.SrcGeoIP.Latitude;
  FFDQueryInsert.ParamByName('pSrcLong').AsFloats[FInsertToArchive]        := aInternalPacket.IP.SrcGeoIP.Longitude;
  {GEOIP DST}
  FFDQueryInsert.ParamByName('pDstLoc').AsStrings[FInsertToArchive]        := aInternalPacket.IP.DestGeoIP.Location;
  FFDQueryInsert.ParamByName('pDstOrg').AsStrings[FInsertToArchive]        := aInternalPacket.IP.DestGeoIP.ASOrganization;  
  FFDQueryInsert.ParamByName('pDstAsn').AsStrings[FInsertToArchive]        := aInternalPacket.IP.DestGeoIP.ASNumber;    
  FFDQueryInsert.ParamByName('pDstLat').AsFloats[FInsertToArchive]         := aInternalPacket.IP.DestGeoIP.Latitude;
  FFDQueryInsert.ParamByName('pDstLong').AsFloats[FInsertToArchive]        := aInternalPacket.IP.DestGeoIP.Longitude;
  FFDQueryInsert.ParamByName('pXMLInfo').AsStrings[FInsertToArchive]       := aInternalPacket.XML_Detail;
  FFDQueryInsert.ParamByName('pPacketRaw').AsAnsiStrings[FInsertToArchive] := aInternalPacket.RAW_Text;


  LMemoryStream := TMemoryStream.Create; 
  Try
    LMemoryStream.WriteBuffer(aInternalPacket.PacketData^,aInternalPacket.PacketSize);

    FFDQueryInsert.ParamByName('pPacket').LoadFromStream(LMemoryStream,ftBlob,FInsertToArchive);

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
  FFDQueryFlow.Close;
  FFDQueryFlow.ParamByName('pIpSrc').AsString    := aIpSrc; 
  FFDQueryFlow.ParamByName('pIpDst').AsString    := aIpDst; 
  FFDQueryFlow.ParamByName('pPortSrc').AsInteger := aPortSrc; 
  FFDQueryFlow.ParamByName('pPortDst').AsInteger := aPortDst;    
  FFDQueryFlow.ParamByName('pIpProto').AsInteger := aIPProto;      
  FFDQueryFlow.Open;
  
  LCurrentIP   := String.Empty;
  LIsClient    := False;
  
  if not FFDQueryFlow.IsEmpty then
  begin
    LStream := TMemoryStream.Create;
    Try
      while not FFDQueryFlow.eof do
      begin
        LStream.Seek(0, soBeginning);
        TBlobField(FFDQueryFlow.FieldByName('PACKET_DATA')).SaveToStream(LStream);
        LPacketSize := LStream.Size;
        GetMem(LPacketData, LPacketSize);
        Try
          LStream.Seek(0, soBeginning);
          LStream.ReadBuffer(LPacketData^, LPacketSize);
          case aIPProto of
           IPPROTO_TCP :  
              begin
                if not TWPcapProtocolBaseTCP.HeaderTCP(LPacketData,LPacketSize,LTCPHdr) then exit;
                LPayLoad     := TWPcapProtocolBaseTCP.GetTCPPayLoad(LPacketData,LPacketSize);
                LPayloadSize := TWPcapProtocolBaseTCP.TCPPayLoadLength(LTCPHdr,LPacketData,LPacketSize)
              end;
           IPPROTO_UDP :
              begin
                if not TWPcapProtocolBaseUDP.HeaderUDP(LPacketData,LPacketSize,LUDPHdr) then exit;
                LPayLoad     := TWPcapProtocolBaseUDP.GetUDPPayLoad(LPacketData,LPacketSize);
                LPayloadSize := TWPcapProtocolBaseUDP.UDPPayLoadLength(LUDPHdr)            
              end
          else
            raise Exception.Create('Error invalid protocolo only TCP and UP protocol are supported');
          end;

          if LCurrentIP <> FFDQueryFlow.FieldByName('IP_SRC').AsString then
          begin
            LCurrentIP := FFDQueryFlow.FieldByName('IP_SRC').AsString;
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
        FFDQueryFlow.Next;
      end;
    finally
      LStream.Free;
    end;    
  end;
  FFDQueryFlow.Close;  
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
  FFDQuerySession.Close;
  FFDQuerySession.ParamByName('pIpSrc').AsString    := aIpSrc; 
  FFDQuerySession.ParamByName('pIpDst').AsString    := aIpDst; 
  FFDQuerySession.ParamByName('pPortSrc').AsInteger := aPortSrc; 
  FFDQuerySession.ParamByName('pPortDst').AsInteger := aPortDst;    
  FFDQuerySession.ParamByName('pIpProto').AsInteger := IPPROTO_UDP;      
  FFDQuerySession.Open;

  if not FFDQuerySession.IsEmpty then
  begin
    LStream := TMemoryStream.Create;
    Try
      LFileRaw := TFileStream.Create(aFilename, fmCreate);
      Try
        while not FFDQuerySession.eof do
        begin
          LStream.Seek(0, soBeginning);
          TBlobField(FFDQuerySession.FieldByName('PACKET_DATA')).SaveToStream(LStream);
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
          FFDQuerySession.Next;
        end;
        Result := True;
      Finally
        FreeAndNil(LFileRaw);
      End;
    finally
      LStream.Free;
    end;    
  end;
  FFDQuerySession.Close;  
end;

destructor TWPcapDBSqLitePacket.Destroy;
begin
  FreeAndNil(FFDQuerySession);
  FreeAndNil(FFDQueryInsert);  
  FreeAndNil(FFDQueryInsertLabel);
  
  FreeAndNil(FFDQueryFlow);
  inherited;
end;

procedure TWPcapDBSqLitePacket.InsertMetadata(const aName: String;aValue: String);
begin
  FFDQueryTmp.SQL.Text                       := 'INSERT INTO METADATA VALUES (:pName,:pValue)';
  FFDQueryTmp.ParamByName('pName').AsString  := aName;
  FFDQueryTmp.ParamByName('pValue').AsString := aValue;  
  FFDQueryTmp.ExecSQL;
end;

procedure TWPcapDBSqLitePacket.SetMaxInsertCache(const Value: SmallInt);
begin
  FMaxInsertCache                 := Value;
  FFDQueryInsert.Params.ArraySize := FMaxInsertCache;  
end;

procedure TWPcapDBSqLitePacket.ResetCounterIntsert;
begin
  FInsertToArchive := -1;
end;

end.
