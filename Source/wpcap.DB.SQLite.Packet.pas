﻿//*************************************************************
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

unit wpcap.DB.SQLite.Packet;

interface

uses
  wpcap.DB.SQLite, wpcap.Protocol.UDP, wpcap.Protocol.TCP, wpcap.protocol, Math,
  wpcap.Conts, FireDAC.Comp.Client, System.Generics.Collections, wpcap.StrUtils,
  FireDAC.Stan.Option, Vcl.Graphics, wpcap.BufferUtils, wpcap.Level.IP,Vcl.Forms,
  wpcap.Types, WinApi.Windows, FireDac.Stan.Param, wpcap.Level.Eth, wpcap.Packet,
  System.Classes, System.Variants, System.SysUtils, Data.Db, System.StrUtils,
  winApi.Winsock2, Wpcap.Protocol.RTP;

  /// <summary>
  /// A class that extends TWPcapDBSqLite and represents a packet stored in a SQLite database.
  /// </summary>  
  type
    TWPcapDBSqLitePacket = Class(TWPcapDBSqLite)
  private
    FFDQueryFlow        : TFDQuery;
    FFDQueryInsert      : TFDQuery;
    FFDQuerySession     : TFDQuery;
    FFDQueryInsertLabel : TFDQuery;
    FFDQueryInsertDNS   : TFDQuery;
    FFDQueryDNSGrid     : TFDQuery;
    FFDQueryLabelList   : TFDQuery;
    FFDUpdateIngnore    : TFDQuery;
    FFDViewUpdate       : TFDUpdateSQL;
    FIngnorePacket      : TList<Integer>;
    FInsertToArchive    : SmallInt;
    FMaxInsertCache     : SmallInt;        
    /// <summary>
    /// Sets the maximum insert cache size.
    /// </summary>
    /// <param name="Value">The maximum insert cache size.</param>    
    procedure SetMaxInsertCache(const Value: SmallInt);
    
    /// <summary>
    /// Retrieves the data from a TFDQuery and stores it in a variant array.
    /// </summary>
    /// <param name="aQuery">The TFDQuery object containing the data to retrieve.</param>
    /// <param name="aArray">Returns the variant array containing the retrieved data.</param>
    /// <param name="aDescription">Returns the description of the retrieved data.</param>
    /// <returns>A boolean value indicating if the operation was successful.</returns>
    Function GetVarArrayByQuery(aQuery:TFdQuery;out aArray : Variant;out aDescription:String):Boolean;
    procedure CreateFDQueryPacketGrid;
    procedure CreateFDQueryDNS;
    procedure CreateFDQueryRapidFilter;
    procedure CreateFDQueryInsertPacket;
  protected

    /// <summary>
    /// Returns the SQL script for the database schema.
    /// </summary>
    /// <returns>A string containing the SQL script for the database schema.</returns>
    function GetSQLScriptDatabaseSchema: String;override;

    /// <summary>
    /// Initializes the database connection.
    /// </summary>    
    procedure InitConnection;override;

    /// <summary>
    /// Inserts metadata into the database.
    /// </summary>
    /// <param name="aName">The name of the metadata to insert.</param>
    /// <param name="aValue">The value of the metadata to insert.</param>    
    procedure InsertMetadata(const aName: String; aValue: String);override;               
  public
    destructor Destroy;override;
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
    /// Resets the insertion counter for the array.
    /// </summary>
    procedure ResetCounterIntsert;

    /// <summary>
    /// Saves the current array to database and clears it from memory.
    /// </summary>
    procedure FlushArrayInsert;
    
    /// <summary>
    /// Retrieves the packet data from the database at the specified packet number.
    /// </summary>
    /// <param name="aNPacket">The packet number to retrieve the data for.</param>
    /// <param name="aPacketSize">The size of the packet data.</param>
    /// <returns>A pointer to the packet data in memory.</returns>    
    function GetPacketDataFromDatabase(aNPacket: Integer;var aPacketSize: Integer;aAdditionalParameters: PTAdditionalParameters): PByte;
    
    /// <summary>
    /// Returns a list of string containing the hexadecimal dump of a packet data with
    /// line by line formatting.
    /// </summary>
    /// <param name="aNPacket">The number of packet to display (starting from 0)</param>
    /// <returns>A list of string containing the hexadecimal dump of the packet data</returns>
    function GetListHexPacket(aNPacket,aStartLevel: Integer;var aListDetail:TListHeaderString): TArray<String>;  

    /// <summary>
    /// Inserts distinct labels into database for filter feature
    /// </summary>
    /// <param name="aListLabelByLevel">The list containing the labels to be inserted.</param>      
    procedure InsertLabelByLevel(const aListLabelByLevel: PTListLabelByLevel);
    /// <summary>
    /// Inserts DNS Resolution into database
    /// </summary>
    /// <param name="aDNSList">The list containing the DNS resolution to be inserted.</param>  
    procedure InsertDNSRecords(const aDNSList: PTDNSRecordDictionary);
    /// <summary>
    /// Retrieves the frame number from the database based on the label passed in.
    /// </summary>
    /// <param name="aArrFrameNumber">Returns the frame number related to the label.</param>
    /// <param name="aLabel">The input label to search for in the database.</param>
    /// <param name="aDescription">Returns the description found for the input label.</param>
    /// <returns>A boolean value indicating if the operation was successful.</returns>    
    function GetFrameNumberByLabel(var aArrFrameNumber: variant; const aLabel: String;var aDescription:String): boolean;    
    
    /// <summary>
    /// Retrieves the flow string for the specified IP addresses and port numbers.
    /// </summary>
    /// <param name="aFlowId">Id of flow.</param>
    /// <param name="aIPProto">The IP protocol number.</param>
    /// <param name="aColorSrc">The color for the source in the flow string.</param>
    /// <param name="aColorDst">The color for the destination in the flow string.</param>
    /// <returns>A TStringList containing the flow string information.</returns>
    Function GetFlowString(const aFlowId,aIPProto:Integer;aColorSrc,aColorDst:TColor):TStringList;

    /// <summary>
    /// Saves the RTP payload data to a file.
    /// </summary>
    /// <param name="aFilename">The name of the file to save the payload data to.</param>
    /// <param name="aFlowID">id of flow.</param>
    /// <param name="aSoxCommand">The command to execute for processing the data.</param>
    /// <returns>A boolean value indicating if the operation was successful.</returns>    
    function SaveRTPPayloadToFile(const aFilename : String;const aFlowID: Integer;var aSoxCommand:String): Boolean;

    function GetContent(const aPathFile: String; const aFlowID,aPacketNumber: Integer;var aFilename: String): Boolean;
    
    constructor Create;override;

    ///<summary>
    /// Rolls back any pending transactions and closes the connection to the SQLite database.
    ///</summary>
    ///<param name="aDelete">
    /// A boolean value indicating whether to delete the database file
    ///</param>
    ///<remarks>
    /// This function performs a rollback of any pending transactions on the SQLite database, and then closes the connection. 
    /// If the aDelete parameter is true,  database file is deleted. 
    /// If there are any errors during the rollback or deletion, it raises an EDatabaseError exception. 
    /// After the connection is closed, all components connected to the database will be disconnected.
    ///</remarks>
    ///<exception cref="EDatabaseError">
    /// An EDatabaseError exception is raised if there are any errors during the rollback or deletion.
    ///</exception>
    procedure RollbackAndClose(aDelete:Boolean);override;

    ///<summary>
    /// Commits pending transactions and closes the connection to the SQLite database.
    ///</summary>
    ///<remarks>
    /// This function performs a commit of any pending transactions on the SQLite database, and then closes the connection. 
    /// If there are any errors during the commit, it raises an EDatabaseError exception. After the connection is closed, 
    /// all components connected to the database will be disconnected.
    ///</remarks>
    ///<exception cref="EDatabaseError">
    /// An EDatabaseError exception is raised if there are any errors during the commit.
    ///</exception>    
    procedure CommitAndClose;override;      
    
    {Property}

    /// <summary>
    /// The maximum insert cache size.
    /// </summary>
    /// <remarks>
    /// This property specifies the maximum size of the insert cache,
    /// which is used to store data before it is inserted into the database.
    /// </remarks>    
    property MaxInsertCache    : SmallInt     read FMaxInsertCache      write SetMaxInsertCache;
    
    /// <summary>
    /// The TFDQuery object used for return list of labels.
    /// </summary>    
    property FDQueryLabelList  : TFDQuery     read FFDQueryLabelList    write FFDQueryLabelList; 

    /// <summary>
    /// The TFDQuery object used for return list of DNS resolution.
    /// </summary>    
    property FDQueryDNSGrid  : TFDQuery       read FFDQueryDNSGrid      write FFDQueryDNSGrid; 
  End;
implementation


function TWPcapDBSqLitePacket.GetSQLScriptDatabaseSchema: String;
{$REGION 'SQL Scrit'}
    CONST SQL_TABLE = 'CREATE TABLE PACKETS (                          '+sLineBreak+
                      '  NPACKET INTEGER PRIMARY KEY ,                 '+sLineBreak+ {Packet}
                      '  PACKET_LEN INTEGER,                           '+sLineBreak+
                      '  PACKET_DATE TEXT,                             '+sLineBreak+
                      '  DIRECTION INTEGER,                            '+sLineBreak+     
                      '  FLOW_ID INTEGER,                              '+sLineBreak+                                        
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
                      '  IS_RETRASMISSION INTEGER,                     '+sLineBreak+ {TCP Additional}                     
                      '  SEQ_NUMBER INTEGER,                           '+sLineBreak+                                          
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
                      '  PACKET_RAW_TEXT TEXT,                         '+sLineBreak+ {Filter}
                      '  XML_PACKET_DETAIL TEXT,                       '+sLineBreak+  
                      '  IGNORE INTEGER,                               '+sLineBreak+  
                      '  COMPRESSION_TYE INTEGER,                      '+sLineBreak+      
                      '  CONTENT_EXT TEXT,                             '+sLineBreak+                                                   
                      '  ENRICHMENT_PRESENT INTEGER,                   '+sLineBreak+                                                               
                      '  PACKET_INFO TEXT,                             '+sLineBreak+                        
                      '  NOTE_PACKET TEXT,                             '+sLineBreak+ {Note} 
                      '  PACKET_DATA BLOB                              '+sLineBreak+ {Data}
                      ');                                              ';

           SQL_INDEX     = 'CREATE UNIQUE INDEX PACKETS_NPACKET_IDX ON PACKETS (NPACKET);  ';
           SQL_INDEX_PKT = 'CREATE INDEX PACKETS_FLOW_ID_IDX ON PACKETS (FLOW_ID);  ';
           SQL_DB_METADATA =  'CREATE TABLE %S(                        '+sLineBreak+
                              '  %S TEXT,                              '+sLineBreak+
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
           


           SQL_VIEW  = 'CREATE VIEW VST_PACKETS AS                                                               ' +sLineBreak+ 
                       'SELECT                                                                                   ' +sLineBreak+ 
                       '  NPACKET, PACKET_LEN, PACKET_DATE,PACKET_RAW_TEXT,XML_PACKET_DETAIL,IS_MALFORMED,       ' +sLineBreak+   {Packet}
                       '  ETH_TYPE, ETH_ACRONYM, MAC_SRC, MAC_DST, IS_IPV6,                                      ' +sLineBreak+   {EThernet}
                       '  PROTO_DETECT, IPPROTO, IPPROTO_STR, IFNULL(PROTOCOL,ETH_ACRONYM) AS PROTOCOL,          ' +sLineBreak+   {IP Protocol}                      
                       '  IFNULL(IP_SRC,MAC_SRC) AS IP_SRC, IFNULL(IP_DST,MAC_DST) AS IP_DST,                    ' +sLineBreak+   {IP IpAddress}   
                       '  PORT_SRC, PORT_DST ,                                                                   ' +sLineBreak+   {TCP/UDP}   
                       '  IS_RETRASMISSION, SEQ_NUMBER , FLOW_ID,                                                ' +sLineBreak+   {TCP additional}  
                       '  IANA_PROTO,                                                                            ' +sLineBreak+   {IANA}   
                       '  SRC_ASN, SRC_ORGANIZZATION, SRC_LOCATION, SRC_LATITUDE, SRC_LONGITUDE,                 ' +sLineBreak+   {GEOIP SRC}
                       '  DST_ASN, DST_ORGANIZZATION, DST_LOCATION, DST_LATITUDE, DST_LONGITUDE,                 ' +sLineBreak+   {GEOIP DST} 
                       '  ENRICHMENT_PRESENT,COMPRESSION_TYE,CONTENT_EXT,                                        ' +sLineBreak+   {Others} 
                       '  NOTE_PACKET,PACKET_INFO,DIRECTION                                                      ' +sLineBreak+      
                       '  FROM PACKETS;';

            SQL_DNS_TABLE = 'CREATE TABLE DNS_RECORDS (        ' +sLineBreak+ 
                            '  RECORD_ID INTEGER PRIMARY KEY,  ' +sLineBreak+ 
                            '  IP_ADDRESS TEXT NOT NULL,       ' +sLineBreak+ 
                            '  HOSTNAME TEXT NOT NULL,         ' +sLineBreak+ 
                            '  TIMESTAMP TEXT NOT NULL, ' +sLineBreak+ 
                            '  TTL_SECONDS INTEGER NOT NULL    ' +sLineBreak+ 
                            ');                                ';

           SQL_INDX_DNS = 'CREATE INDEX IDX_IP_DNS_RECORD ON DNS_RECORDS (IP_ADDRESS); ';
           

{$ENDREGION}
begin
  Result := SQL_TABLE            +sLineBreak+
            SQL_INDEX            +sLineBreak+
            SQL_INDEX_PKT         +sLineBreak+
            SQL_VIEW             +sLineBreak+            
            SQL_DB_LABEL_FILTER  +sLineBreak+
            SQL_INDEX_LF_1       +sLineBreak+
            SQL_INDEX_LF_2       +sLineBreak+
            SQL_DNS_TABLE        +sLineBreak+
            SQL_INDX_DNS         +sLineBreak+
            Format(SQL_DB_METADATA,[GetMetadataTableName,GetMetadataCOLUMN_NAME_NAME,GetMetadataCOLUMN_NAME_VALUE]);
end;

    
{TODO split in sub procedure}
procedure TWPcapDBSqLitePacket.InitConnection;
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
  FMaxInsertCache                                           := 2000; 

  CreateFDQueryInsertPacket;
  CreateFDQueryRapidFilter;
  CreateFDQueryDNS;
  CreateFDQueryPacketGrid;
end; 

Procedure TWPcapDBSqLitePacket.CreateFDQueryInsertPacket;
{$REGION 'SQL insert}
CONST SQL_INSERT = 'INSERT INTO PACKETS(                                                                     ' +slineBreak+
                   '  NPACKET,PACKET_LEN, PACKET_DATE, PACKET_DATA,PACKET_RAW_TEXT,XML_PACKET_DETAIL, IS_MALFORMED,  ' +sLineBreak+   {Packet}
                   '  ETH_TYPE, ETH_ACRONYM, MAC_SRC, MAC_DST, IS_IPV6,                                      ' +sLineBreak+   {EThernet}
                   '  PROTO_DETECT, IPPROTO, IPPROTO_STR, PROTOCOL,                                          ' +sLineBreak+   {IP Protocol}                      
                   '  IP_SRC,  IP_DST,                                                                       ' +sLineBreak+   {IP IpAddress}   
                   '  PORT_SRC, PORT_DST,                                                                    ' +sLineBreak+   {TCP/UDP}   
                   '  IS_RETRASMISSION, SEQ_NUMBER ,FLOW_ID ,                                                ' +sLineBreak+   {TCP additional}                     
                   '  IANA_PROTO,                                                                            ' +sLineBreak+   {IANA}   
                   '  SRC_ASN, SRC_ORGANIZZATION, SRC_LOCATION, SRC_LATITUDE, SRC_LONGITUDE,                 ' +sLineBreak+   {GEOIP SRC}
                   '  DST_ASN, DST_ORGANIZZATION, DST_LOCATION, DST_LATITUDE, DST_LONGITUDE,                 ' +sLineBreak+   {GEOIP DST}   
                   '  ENRICHMENT_PRESENT,COMPRESSION_TYE,IGNORE, CONTENT_EXT,                                ' +sLineBreak+   {Others}                    
                   '  PACKET_INFO,DIRECTION                                                                  ' +sLineBreak+
                   ' )                                                                                       ' +sLineBreak+   
                   'VALUES                                                                                   ' +slineBreak+
                   ' (:pID,:pLen,:pDate,:pPacket,:pPacketRaw,:pXMLInfo,:pIsMalformed ,                            ' +sLineBreak+   {Packet}
                   '  :pEthType,:pEthAcr,:pMacSrc,:pMacDst,:pIsIPV6,                                         ' +sLineBreak+   {EThernet}
                   '  :pProtoDetect,:pIpProto,:pIpProtoStr,:pProto,                                          ' +sLineBreak+   {IP Protocol} 
                   '  :pIpSrc,:pIpDst,                                                                       ' +sLineBreak+   {IP IpAddress}
                   '  :pPortSrc,:pPortDst,                                                                   ' +sLineBreak+   {TCP/UDP}   
                   '  :pIsRetrasmission, :pSeqNumber ,:pFlowID,                                              ' +sLineBreak+   {TCP additional}                     
                   '  :pProtoIANA,                                                                           ' +sLineBreak+   {IANA} 
                   '  :pSrcAsn,:pSrcOrg,:pSrcLoc,:pSrcLat,:pSrcLong,                                         ' +sLineBreak+   {GEOIP SRC}
                   '  :pDstAsn,:pDstOrg,:pDstLoc,:pDstLat,:pDstLong,                                         ' +sLineBreak+   {GEOIP DST} 
                   '  :pEnrichmentPresent,:pCopressionType,:pIgnore,:pContentExt,                            ' +sLineBreak+
                   '  :pPacketInfo,:pDirection                                                               ' +sLineBreak+
                   ')';
{$ENDREGION}
begin
  FFDQueryInsert                                            := TFDQuery.Create(nil);
  FFDQueryInsert.Connection                                 := FConnection;    
  FFDQueryInsert.SQL.Text                                   := SQL_INSERT; 
  FFDQueryInsert.ParamByName('pID').DataType                := ftInteger; {Packet}
  FFDQueryInsert.ParamByName('pLen').DataType               := ftInteger; 
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
  FFDQueryInsert.ParamByName('pIsRetrasmission').DataType   := ftInteger; {TCP/additional}      
  FFDQueryInsert.ParamByName('pSeqNumber').DataType         := ftInteger;   
  FFDQueryInsert.ParamByName('pFlowID').DataType            := ftInteger;   
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
  FFDQueryInsert.ParamByName('pPacketRaw').DataType         := ftString;    
  FFDQueryInsert.ParamByName('pDstLat').DataType            := ftFloat;   
  FFDQueryInsert.ParamByName('pDstLong').DataType           := ftFloat;
  FFDQueryInsert.ParamByName('pPacketInfo').DataType        := ftString;    
  FFDQueryInsert.ParamByName('pEnrichmentPresent').DataType := ftInteger;
  FFDQueryInsert.ParamByName('pCopressionType').DataType    := ftInteger;
  FFDQueryInsert.ParamByName('pContentExt').DataType        := ftString;    
  FFDQueryInsert.ParamByName('pIgnore').DataType            := ftInteger;     
  FFDQueryInsert.ParamByName('pDirection').DataType         := ftInteger;      
  FFDQueryInsert.ParamByName('pPacket').DataType            := ftblob;   
  FFDQueryInsert.CachedUpdates                              := True;   

end;

Procedure TWPcapDBSqLitePacket.CreateFDQueryRapidFilter;
begin
  FFDGetDataByID.SQL.Text                                   := 'SELECT PACKET_DATA,IS_RETRASMISSION,SEQ_NUMBER,PACKET_INFO,PACKET_DATE FROM PACKETS WHERE NPACKET = :pNPACKET '; 

  FFDQueryFlow                                              := TFDQuery.Create(nil);
  FFDQueryFlow.Connection                                   := FConnection;
  FFDQueryFlow.SQL.Text                                     := 'SELECT IP_SRC,IP_DST,PORT_SRC,PORT_DST,PACKET_DATA,COMPRESSION_TYE FROM PACKETS          '+sLineBreak+ 
                                                               'WHERE FLOW_ID = :pFlowID AND IGNORE = 0 ORDER BY SEQ_NUMBER,PACKET_DATE ASC';

  FFDQuerySession                                            := TFDQuery.Create(nil);
  FFDQuerySession.Connection                                 := FConnection;
  FFDQuerySession.SQL.Text                                   := 'SELECT IP_SRC,IP_DST,PORT_SRC,PORT_DST,PACKET_DATA,PROTO_DETECT,COMPRESSION_TYE,CONTENT_EXT,NPACKET FROM PACKETS   '+sLineBreak+ 
                                                                'WHERE  FLOW_ID = :pFlowID AND IGNORE = 0 ORDER BY SEQ_NUMBER, PACKET_DATE ASC';     

  FFDQueryInsertLabel                                        := TFDQuery.Create(nil);
  FFDQueryInsertLabel.Connection                             := FConnection;
  FFDQueryInsertLabel.SQL.Text                               := 'INSERT INTO LABEL_FILTER (ID_LABEL_NAME,LABEL_NAME,DESCRIPTION,LEVEL,ID_PARENT) VALUES (:pIdLabel,:pLabelName,:pDescription,:pLevel,:pIdParent)';
  FFDQueryInsertLabel.ParamByName('pIdLabel').DataType       := ftInteger; 
  FFDQueryInsertLabel.ParamByName('pLabelName').DataType     := ftString;
  FFDQueryInsertLabel.ParamByName('pDescription').DataType   := ftString;
  FFDQueryInsertLabel.ParamByName('pLevel').DataType         := ftInteger; 
  FFDQueryInsertLabel.ParamByName('pIdParent').DataType      := ftInteger;    
  
  FFDQueryLabelList                                          := TFDQuery.Create(nil);
  FFDQueryLabelList.Connection                               := FConnection;
  FFDQueryLabelList.SQL.Text                                 := 'SELECT * FROM LABEL_FILTER';  
end;

Procedure TWPcapDBSqLitePacket.CreateFDQueryDNS;
begin  
  FFDQueryDNSGrid                                            := TFDQuery.Create(nil);
  FFDQueryDNSGrid.Connection                                 := FConnection;
  FFDQueryDNSGrid.SQL.Text                                   := 'SELECT * FROM DNS_RECORDS ORDER BY RECORD_ID';
    
  FFDQueryInsertDNS                                          := TFDQuery.Create(nil);
  FFDQueryInsertDNS.Connection                               := FConnection;
  FFDQueryInsertDNS.SQL.Text                                 := 'INSERT INTO DNS_RECORDS (IP_ADDRESS,HOSTNAME,TIMESTAMP,TTL_SECONDS) VALUES (:pIP,:pHostname,:pTimeStamp,:pTTL)';
  FFDQueryInsertDNS.ParamByName('pIP').DataType              := ftString;
  FFDQueryInsertDNS.ParamByName('pHostname').DataType        := ftString;
  FFDQueryInsertDNS.ParamByName('pTimeStamp').DataType       := ftString; 
  FFDQueryInsertDNS.ParamByName('pTTL').DataType             := ftInteger;          
end;

Procedure TWPcapDBSqLitePacket.CreateFDQueryPacketGrid;
begin
  FFDQueryGrid.SQL.Text                                     := 
                                                                 'SELECT                                                                                 ' +sLineBreak+ 
                                                               '  NPACKET, PACKET_LEN, PACKET_DATE,IS_MALFORMED,PACKET_INFO,                              ' +sLineBreak+ 
                                                               '  ETH_TYPE, ETH_ACRONYM, MAC_SRC, MAC_DST, IS_IPV6,                                      ' +sLineBreak+   {EThernet}
                                                               '  PROTO_DETECT, IPPROTO, IPPROTO_STR, IFNULL(PROTOCOL,ETH_ACRONYM) AS PROTOCOL,          ' +sLineBreak+   {IP Protocol}                      
                                                               '  IFNULL(IP_SRC,MAC_SRC) AS IP_SRC, IFNULL(IP_DST,MAC_DST) AS IP_DST,                    ' +sLineBreak+   {IP IpAddress}   
                                                               '  PORT_SRC, PORT_DST,                                                                    ' +sLineBreak+   {TCP/UDP}   
                                                               '  IS_RETRASMISSION, SEQ_NUMBER ,FLOW_ID,                                                 ' +sLineBreak+   {TCP additional}                                                                
                                                               '  IANA_PROTO,                                                                            ' +sLineBreak+   {IANA}   
                                                               '  SRC_ASN, SRC_ORGANIZZATION, SRC_LOCATION, SRC_LATITUDE, SRC_LONGITUDE,                 ' +sLineBreak+   {GEOIP SRC}
                                                               '  DST_ASN, DST_ORGANIZZATION, DST_LOCATION, DST_LATITUDE, DST_LONGITUDE,NOTE_PACKET,     ' +sLineBreak+   {GEOIP DST} 
                                                               '  ENRICHMENT_PRESENT,COMPRESSION_TYE ,CONTENT_EXT,DIRECTION                              ' +sLineBreak+ 
                                                               '  FROM VST_PACKETS ORDER BY NPACKET ';            


  FFDUpdateIngnore                                           := TFDQuery.Create(nil);
  FFDUpdateIngnore.Connection                                := FConnection;
  FFDUpdateIngnore.SQL.Text                                  := 'UPDATE PACKETS SET IGNORE = 1 WHERE NPACKET = :PNPacket';
  FFDUpdateIngnore.ParamByName('PNPacket').DataType          := ftInteger;
  
  FFDViewUpdate                                              := TFDUpdateSQL.Create(nil);
  FFDViewUpdate.Connection                                   := FConnection;
  FFDViewUpdate.ModifySQL.Text                               := 'UPDATE PACKETS SET NOTE_PACKET = :NOTE_PACKET WHERE NPACKET = :NPACKET ';
  FFDQueryGrid.UpdateObject                                  := FFDViewUpdate;
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
var lQuery  : TFdQuery;
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

procedure TWPcapDBSqLitePacket.InsertDNSRecords(const aDNSList: PTDNSRecordDictionary);
var AIndex    : Integer; 
    Literator : TDictionary<Uint16, TDNSRecord>.TPairEnumerator;
begin
  if aDNSList.Count = 0 then Exit;

  if not FFDQueryInsertDNS.Prepared then
    FFDQueryInsertDNS.Prepare;

  FFDQueryInsertDNS.Params.ArraySize := aDNSList.Count-1;

  Literator := aDNSList.GetEnumerator();  
  AIndex    := 0;
  Literator.MoveNext;
  Try
    while AIndex < aDNSList.Count -1 do
    begin
      if not Literator.Current.Value.IPAddress.IsEmpty then
      begin
        FFDQueryInsertDNS.ParamByName('pIp').AsStrings[AIndex]    := Literator.Current.Value.IPAddress;
        FFDQueryInsertDNS.ParamByName('pHostname').AsStrings[AIndex]   := Literator.Current.Value.Hostname;
        FFDQueryInsertDNS.ParamByName('pTimeStamp').AsStrings[AIndex]  := DateTimeToStr(Literator.Current.Value.Timestamp);
        FFDQueryInsertDNS.ParamByName('pTTL').AsIntegers[AIndex]       := Literator.Current.Value.TTL;
        Inc(AIndex);
      end;
      Literator.MoveNext;
    end;   
    if AIndex > 0 then
      FFDQueryInsertDNS.Execute(AIndex); // esegue la batch insert            
  except on e: Exception do 
    DoLog('TWPcapDBSqLitePacket.InsertDNSRecords',e.message,TWLLException);
  end;
end;


procedure TWPcapDBSqLitePacket.InsertLabelByLevel(const aListLabelByLevel : PTListLabelByLevel);
var Literator : TDictionary<String, TLabelByLevel>.TPairEnumerator;

    procedure AddLabelFilter(const aIdParent,aLevel: Integer;var AIndex:Integer);
    var aParent : Integer;
    begin
      if Literator.Current.Value.LabelName.Trim.IsEmpty then exit;

      aParent := AIndex;  
      FFDQueryInsertLabel.ParamByName('pIdLabel').AsIntegers[AIndex]     := AIndex+1;
      FFDQueryInsertLabel.ParamByName('pLabelName').AsStrings[AIndex]    := Literator.Current.Value.LabelName;
      FFDQueryInsertLabel.ParamByName('pDescription').AsStrings[AIndex]  := Literator.Current.Value.Description;
      FFDQueryInsertLabel.ParamByName('pLevel').AsIntegers[AIndex]       := aLevel;

      if aIdParent > 0 then
        FFDQueryInsertLabel.ParamByName('pIdParent').AsIntegers[AIndex] := aIdParent
      else
        FFDQueryInsertLabel.ParamByName('pIdParent').Clear;
      Inc(AIndex);
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
  FFDQueryInsertLabel.Params.ArraySize := aListLabelByLevel.Count-1;
  Literator := aListLabelByLevel.GetEnumerator();  

  i := 0;
  Literator.MoveNext;
  while I < aListLabelByLevel.Count -1 do
    AddLabelFilter(0,Literator.Current.Value.Level,I); 
  Try    
    FFDQueryInsertLabel.Execute(I); // esegue la batch insert        
  except on e: Exception do 
    DoLog('TWPcapDBSqLitePacket.InsertLabelByLevel',e.message,TWLLException);
  end;
end;

procedure TWPcapDBSqLitePacket.FlushArrayInsert;
begin
  if FInsertToArchive > -1 then
  begin
    DoLog('TWPcapDBSqLitePacket.FlushArrayInsert',Format('Insert [%d] elements',[FInsertToArchive]),TWLLInfo);
    FFDQueryInsert.Execute(FInsertToArchive);
  end;
  ResetCounterIntsert;
end;

procedure TWPcapDBSqLitePacket.InsertPacket(const aInternalPacket : PTInternalPacket);
var LMemoryStream : TMemoryStream;
begin
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
  FFDQueryInsert.ParamByName('pLen').AsIntegers[FInsertToArchive]         := aInternalPacket.AdditionalInfo.Index;

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

  {Additional}      
  FFDQueryInsert.ParamByName('pIsRetrasmission').AsIntegers[FInsertToArchive]   := ifthen(aInternalPacket.AdditionalInfo.TCP.Retrasmission,1,0);  
  FFDQueryInsert.ParamByName('pEnrichmentPresent').AsIntegers[FInsertToArchive] := ifthen(aInternalPacket.AdditionalInfo.EnrichmentPresent,1,0);  
  FFDQueryInsert.ParamByName('pContentExt').AsStrings[FInsertToArchive]         := aInternalPacket.AdditionalInfo.ContentExt;
  FFDQueryInsert.ParamByName('pDirection').AsIntegers[FInsertToArchive]         := Integer(aInternalPacket.AdditionalInfo.Direction);

  FFDQueryInsert.ParamByName('pIgnore').AsIntegers[FInsertToArchive]            := 0; 

  if aInternalPacket.AdditionalInfo.CompressType > -1 then  
    FFDQueryInsert.ParamByName('pCopressionType').AsIntegers[FInsertToArchive] := aInternalPacket.AdditionalInfo.CompressType
  else
    FFDQueryInsert.ParamByName('pCopressionType').Clear(FInsertToArchive);
  
  if aInternalPacket.AdditionalInfo.SequenceNumber > 0 then  
    FFDQueryInsert.ParamByName('pSeqNumber').AsIntegers[FInsertToArchive] := aInternalPacket.AdditionalInfo.SequenceNumber
  else
    FFDQueryInsert.ParamByName('pSeqNumber').Clear(FInsertToArchive);

  if aInternalPacket.AdditionalInfo.FlowID > 0 then  
    FFDQueryInsert.ParamByName('pFlowId').AsIntegers[FInsertToArchive] := aInternalPacket.AdditionalInfo.FlowID
  else
    FFDQueryInsert.ParamByName('pFlowId').Clear(FInsertToArchive);

   if aInternalPacket.AdditionalInfo.TCP.RetrasmissionFn > 0 then
    FIngnorePacket.Add(aInternalPacket.AdditionalInfo.TCP.RetrasmissionFn); 
  
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
  {Filter}
  FFDQueryInsert.ParamByName('pXMLInfo').AsStrings[FInsertToArchive]       := aInternalPacket.XML_Detail;
  FFDQueryInsert.ParamByName('pPacketRaw').AsAnsiStrings[FInsertToArchive] := aInternalPacket.RAW_Text;  
  {Info}
  FFDQueryInsert.ParamByName('pPacketInfo').AsStrings[FInsertToArchive]    := aInternalPacket.AdditionalInfo.Info;   
  LMemoryStream := TMemoryStream.Create; 
  Try
    LMemoryStream.WriteBuffer(aInternalPacket.PacketData^,aInternalPacket.PacketSize);
    FFDQueryInsert.ParamByName('pPacket').LoadFromStream(LMemoryStream,ftBlob,FInsertToArchive);
  Finally
    FreeAndNil(LMemoryStream);
  End;  
end;

Function TWPcapDBSqLitePacket.GetPacketDataFromDatabase(aNPacket:Integer;var aPacketSize:Integer;aAdditionalParameters: PTAdditionalParameters):PByte;
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
      aAdditionalParameters.TCP.Retrasmission := FFDGetDataByID.FieldByName('IS_RETRASMISSION').AsInteger = 1;     
      aAdditionalParameters.SequenceNumber    := FFDGetDataByID.FieldByName('SEQ_NUMBER').AsInteger;
      aAdditionalParameters.PacketDate        := StrToDateTime(FFDGetDataByID.FieldByName('PACKET_DATE').AsString);
      aAdditionalParameters.Info              := FFDGetDataByID.FieldByName('PACKET_INFO').AsString;
      aAdditionalParameters.DNSList           := nil;
    finally
      LStream.Free;
    end;    
  end;
  FFDGetDataByID.Close;  
end;

Function TWPcapDBSqLitePacket.GetListHexPacket(aNPacket,aStartLevel:Integer;var aListDetail:TListHeaderString):TArray<String>;
var LPacket       : PByte;
    LPacketSize   : Integer;
    LAdditionInfo : TAdditionalParameters;
begin
  SetLength(Result,0);
  LPacket := GetPacketDataFromDatabase(aNPacket,LPacketSize,@LAdditionInfo);
  if Assigned(LPacket) then
  begin
    Try
      Result := DisplayHexData(LPacket,LPacketSize);
      TWpcapEthHeader.HeaderToString(LPacket,LPacketSize,aStartLevel,aListDetail,False,@LAdditionInfo);
    Finally
      FreeMem(LPacket);
    End;
  end;
end;

function TWPcapDBSqLitePacket.GetFlowString(const aFlowId,aIPProto: Integer; aColorSrc, aColorDst: TColor): TStringList;
CONST HTML_FORMAT = '<pre class="%s">%s</pre>';
var LPacketSize : Integer;
    LPacketData : PByte;
    LStream     : TMemoryStream;
    LPayLoad    : PByte;
    LCurrentIP  : String; 
    LIsClient   : Boolean;
    LPayloadSize: Integer;
    LDummy      : Integer;
begin
  Result := TStringList.Create;
  FFDQueryFlow.Close;
  FFDQueryFlow.ParamByName('pFlowID').AsInteger := aFlowId;   
  FFDQueryFlow.Open;
  
  LCurrentIP := String.Empty;
  LIsClient  := False;
  
  if not FFDQueryFlow.IsEmpty then
  begin
    LStream := TMemoryStream.Create;
    Try
      while not FFDQueryFlow.eof do
      begin
        LStream.Seek(0, soBeginning);
        LStream.Clear;
        TBlobField(FFDQueryFlow.FieldByName('PACKET_DATA')).SaveToStream(LStream);
        LPacketSize := LStream.Size;
        GetMem(LPacketData, LPacketSize);
        Try
          LStream.Seek(0, soBeginning);
          LStream.ReadBuffer(LPacketData^, LPacketSize);
          case aIPProto of
           IPPROTO_TCP : LPayLoad := TWPcapProtocolBaseTCP.GetPayLoad(LPacketData,LPacketSize,LPayloadSize,LDummy);
           IPPROTO_UDP : LPayLoad := TWPcapProtocolBaseUDP.GetPayLoad(LPacketData,LPacketSize,LPayloadSize,LDummy);           
          else
            begin
              DoLog('TWPcapDBSqLitePacket.GetFlowString',Format('Error invalid protocol [%d] only TCP and UP protocol are supported',[aIPProto]),TWLLException);
              raise Exception.Create('Error invalid protocol only TCP and UP protocol are supported');
            end;
          end;

          if LCurrentIP <> FFDQueryFlow.FieldByName('IP_SRC').AsString then
          begin
            LCurrentIP := FFDQueryFlow.FieldByName('IP_SRC').AsString;
            LIsClient  := not  LIsClient;
            
            if Result.Count = 0 then
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

function TWPcapDBSqLitePacket.GetContent(const aPathFile : String;const aFlowID,aPacketNumber:Integer;var aFilename:String): Boolean;
var LPacketSize       : Integer;
    LPacketData       : PByte;
    LStream           : TMemoryStream;
    LPayLoad          : PByte;
    LPayloadSize      : Integer;
    LFileRaw          : TFileStream;
    LUDPProtoDetected : TWPcapProtocolBaseUDP;	
    LTCPProtoDetected : TWPcapProtocolBaseTCP;
    LExt              : String;
    LSizeTotal        : Integer;
    LSizeDummy        : Integer;
begin
  Result      := False;
  LSizeTotal  := 0;
  FFDQuerySession.Close;
  FFDQuerySession.ParamByName('pFlowId').asInteger    := aFlowID;       
  FFDQuerySession.Open;

  if not FFDQuerySession.IsEmpty then
  begin
    LStream := TMemoryStream.Create;
    Try
      LExt := String.Empty;

      while not FFDQuerySession.Eof do
      begin     
        if aPacketNumber = FFDQuerySession.FieldByName('NPACKET').AsInteger then
        begin
          LExt := FFDQuerySession.FieldByName('CONTENT_EXT').AsString;
          Break;
        end;
        FFDQuerySession.Next;
      end;
      
      aFilename := Format('%sFile_%d.%s',[aPathFile,aPacketNumber,LExt]);   
      DeleteFile(aFilename);
      LFileRaw  := TFileStream.Create(aFilename, fmCreate);

      Try
        while not FFDQuerySession.Eof do
        begin
          LUDPProtoDetected := nil;
          LTCPProtoDetected := FListProtolsTCPDetected.GetListByIDProtoDetected(FFDQuerySession.FieldByName('PROTO_DETECT').AsInteger);
          if not Assigned(LTCPProtoDetected) then  
            LUDPProtoDetected := FListProtolsUDPDetected.GetListByIDProtoDetected(FFDQuerySession.FieldByName('PROTO_DETECT').AsInteger);

          LStream.Clear;
          LStream.Seek(0, soBeginning);
          TBlobField(FFDQuerySession.FieldByName('PACKET_DATA')).SaveToStream(LStream);
          LPacketSize := LStream.Size;
          if LPacketSize > 1 then
          begin
            GetMem(LPacketData, LPacketSize);
            Try

              LStream.Seek(0, soBeginning);
              LStream.ReadBuffer(LPacketData^, LPacketSize);
              LPayLoad     := nil;
              LPayloadSize := 0;
              if FFDQuerySession.FieldByName('PROTO_DETECT').AsInteger = DETECT_PROTO_TCP then
                 LPayLoad := TWPcapProtocolBaseTCP.GetPayLoad(LPacketData,LPacketSize,LPayloadSize,LSizeDummy)

              else if FFDQuerySession.FieldByName('PROTO_DETECT').AsInteger = DETECT_PROTO_UDP then
                 LPayLoad := TWPcapProtocolBaseUDP.GetPayLoad(LPacketData,LPacketSize,LPayloadSize,LSizeDummy)
              else if Assigned(LTCPProtoDetected) then            
                LPayLoad    := LTCPProtoDetected.GetPayLoad(LPacketData,LPacketSize,LPayloadSize,LSizeTotal)
              else if Assigned(LUDPProtoDetected) then
                LPayLoad    := LUDPProtoDetected.GetPayLoad(LPacketData,LPacketSize,LPayloadSize,LSizeTotal); 
              if (LPayLoad <> nil) and (LPayloadSize > 0) then
                LFileRaw.WriteBuffer(LPayLoad^, LPayloadSize);

           
            Finally
              FreeMem(LPacketData)
            End;
          end;
        
          if LSizeTotal > LFileRaw.Size then
            FFDQuerySession.Next
          else break;          
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

function TWPcapDBSqLitePacket.SaveRTPPayloadToFile(const aFilename : String;const aFlowID:Integer;var aSoxCommand:String): Boolean;
var LPacketSize : Integer;
    LPacketData : PByte;
    LStream     : TMemoryStream;
    LPayLoad    : PByte;
    LPayloadSize: Integer;
    LFileRaw    : TFileStream;
    LSizeTotal  : Integer;
begin
  Result      := False;
  aSoxCommand := String.Empty;
  FFDQuerySession.Close;
  FFDQuerySession.ParamByName('pFlowId').asInteger    := aFlowID;       
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

            LPayLoad    := TWPcapProtocolRTP.GetPayLoad(LPacketData,LPacketSize,LPayloadSize,LSizeTotal); 
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

constructor TWPcapDBSqLitePacket.Create;
begin
  inherited;
  FIngnorePacket := TList<Integer>.Create;  
end;

destructor TWPcapDBSqLitePacket.Destroy;
begin
  FreeAndNil(FFDQuerySession);
  FreeAndNil(FIngnorePacket);    
  FreeAndNil(FFDUpdateIngnore);        
  FreeAndNil(FFDQueryInsert);  
  FreeAndNil(FFDQueryInsertDNS);  
  FreeAndNil(FFDQueryDNSGrid);  
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

procedure TWPcapDBSqLitePacket.RollbackAndClose(aDelete: Boolean);
begin
  inherited;
  FIngnorePacket.Clear;
end;

procedure TWPcapDBSqLitePacket.CommitAndClose;
var I : integer;
begin
  if FIngnorePacket.Count > 0 then
  begin
    FFDUpdateIngnore.Prepare;
    FFDUpdateIngnore.Params.ArraySize := FIngnorePacket.Count-1;    
  end;

  for I := 0 to FIngnorePacket.Count-1 do
    FFDUpdateIngnore.Params[0].AsIntegers[I] := FIngnorePacket[I];  

  if FIngnorePacket.Count > 0 then
  begin
    DoLog('TWPcapDBSqLitePacket.CommitAndClose',Format('Found [%d] elements to be ingored',[FIngnorePacket.Count]),TWLLInfo);
    FFDUpdateIngnore.Execute(FIngnorePacket.Count -1);
  end;
    
  inherited;
  FIngnorePacket.Clear;
end;

end.



