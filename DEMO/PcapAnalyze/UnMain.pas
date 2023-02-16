unit UnMain;

interface
                                                            
uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, WinSock,
  Vcl.StdCtrls, wpcap.protocol, cxGraphics, cxControls, cxCustomData, dateUtils,
  wpcap.StrUtils, cxGridCustomTableView, cxGridTableView, cxGridLevel, cxClasses,
  cxGrid, wpcap.wrapper, wpcap.Conts, wpcap.Types, cxLookAndFeels, System.IOUtils,
  cxLookAndFeelPainters, dxSkinsCore, cxStyles, cxFilter, cxData, cxDataStorage,
  cxEdit, cxNavigator, dxDateRanges, dxScrollbarAnnotations, cxGridCustomView,
  cxContainer, cxProgressBar;

type
  TForm2 = class(TForm)
    Button1: TButton;
    OpenDialog1: TOpenDialog;
    GridPcapLevel1: TcxGridLevel;
    GridPcap: TcxGrid;
    GridPcapTableView1: TcxGridTableView;
    GridPcapTableView1COUNT: TcxGridColumn;
    GridPcapTableView1SRC: TcxGridColumn;
    GridPcapTableView1DST: TcxGridColumn;
    GridPcapTableView1PROTO: TcxGridColumn;
    GridPcapTableView1LEN: TcxGridColumn;
    GridPcapTableView1DATA: TcxGridColumn;
    cxProgressBar1: TcxProgressBar;
    GridPcapTableView1PORTSRC: TcxGridColumn;
    GridPcapTableView1MACSrc: TcxGridColumn;
    GridPcapTableView1MacDst: TcxGridColumn;
    GridPcapTableView1PORTDST: TcxGridColumn;
    GridPcapTableView1ETHTYPE: TcxGridColumn;
    GridPcapTableView1ETHTYPENUM: TcxGridColumn;
    GridPcapTableView1IPPROTO: TcxGridColumn;
    procedure Button1Click(Sender: TObject);
    procedure GridPcapTableView1TcxGridDataControllerTcxDataSummaryFooterSummaryItems0GetText(
      Sender: TcxDataSummaryItem; const AValue: Variant; AIsFooter: Boolean;
      var AText: string);
  private
    procedure OpenPcap(const aFileName: String);
    procedure SetPositionProgressBar(aNewPos: Int64);
    function FileGetSize(const FileName: string): Int64;
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form2: TForm2;

implementation

{$R *.dfm}

Procedure TForm2.SetPositionProgressBar(aNewPos : Int64);
begin
  cxProgressBar1.Position := aNewPos;
  if Trunc( (aNewPos * 100) / cxProgressBar1.Properties.Max) Mod 5 = 0 then                
    cxProgressBar1.Update
end;

function TForm2.FileGetSize(const FileName: string): Int64;
var FileAttributesEx: WIN32_FILE_ATTRIBUTE_DATA;
    OldMode         : Cardinal;
    Size            : ULARGE_INTEGER;
begin
  Result  := -1;
  OldMode := SetErrorMode(SEM_FAILCRITICALERRORS);
  try
    if GetFileAttributesEx(PChar(FileName), GetFileExInfoStandard, @FileAttributesEx) then
    begin
      Size.LowPart  := FileAttributesEx.nFileSizeLow;
      Size.HighPart := FileAttributesEx.nFileSizeHigh;
      Result        := Size.QuadPart;
    end;
  finally
    SetErrorMode(OldMode);
  end;
end;

procedure TForm2.OpenPcap(const aFileName:String);
var LHandlePcap      : Ppcap_t;
    LErrbuf          : array[0..PCAP_ERRBUF_SIZE-1] of AnsiChar;
    LHeader          : PTpcap_pkthdr;
    LPktData         : PByte;
    LResultPcapNext  : Integer;
    LIndexPacket     : int64;
    LProtoMapping    : String;
    LIPHdr           : PETHHdr;
    LEthType         : Word;
    LIPv6Hdr         : PIPv6Header;
    LLenAnalyze      : Int64;
begin
  Caption := Format('PCAP Analisys %s',[ExtractFileName(aFileName)]);
  GridPcapTableView1.DataController.RecordCount := 0;
  GridPcapTableView1.DataController.BeginUpdate;
  SetPositionProgressBar(0);
  Try
    {TODO 
      Thread with syncronize
      Database SQLLIte
      Query bulder 
      Filter WIncap
      Packet detail
      TcpFlow 
      UdpFlow
      ChartStatistics by protocol
      Grid with port
      Grid with Mac
      Grid with EthType e IP Proto with hidden column by default...
      Color for grid
      
    }
    LLenAnalyze                   := 0;
    cxProgressBar1.Properties.Max := FileGetSize(aFileName);
    LHandlePcap := pcap_open_offline(PAnsiChar(AnsiString(aFileName)), LErrbuf);
    if LHandlePcap = nil then
    begin
      ShowMessage('Errore durante l''apertura del file PCAP: ' + string(LErrbuf));
      Exit;
    end;

    try

      // Loop over packets in PCAP file
      while True do
      begin
        // Read the next packet
        LResultPcapNext := pcap_next_ex(LHandlePcap, LHeader, @LPktData);
        case LResultPcapNext of
          1:  // packet read correctly           
            begin           
              LIPHdr       := PETHHdr(LPktData);
              LEthType     := ntohs(LIPHdr.EtherType);
              LIndexPacket := GridPcapTableView1.DataController.AppendRecord;
              Inc(LLenAnalyze,LHeader.len);
              SetPositionProgressBar(LLenAnalyze);
              {Common packet info}
              GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1COUNT.Index]       := LIndexPacket+1;
              GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1LEN.Index]         := LHeader.len;              
              GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1DATA.Index]        := UnixToDateTime(LHeader.ts.tv_sec,false);    
              GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1ETHTYPE.Index]     := GetEthAcronymName(LEthType);
              GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1ETHTYPENUM.Index]  := LEthType;
              GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1MACSrc.Index]      := MACAddrToStr(LIPHdr.SrcAddr);
              GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1MacDst.Index]      := MACAddrToStr(LIPHdr.DestAddr);              
              
              case LEthType of
                ETH_P_IP :
                  begin
                    LProtoMapping                                                                          := GetIPv4ProtocolName(PIPHeader(LPktData + ETH_HEADER_LEN).Protocol);
                    GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1SRC.Index]     := intToIPV4(PIPHeader(LPktData + ETH_HEADER_LEN).SrcIP.Addr );
                    GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1DST.Index]     := intToIPV4(PIPHeader(LPktData + ETH_HEADER_LEN).DestIP.Addr );
                    GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1IPPROTO.Index] := PIPHeader(LPktData + ETH_HEADER_LEN).Protocol;


                    case PIPHeader(LPktData + ETH_HEADER_LEN).Protocol of
                      IPPROTO_UDP:
                        begin 
                         // if IsNTPPacket(LPktData,LHeader.len ) then
                         //   LProtoMapping := 'NTP'
                          //else 
                          if IsL2TPPacketData(LPktData,LHeader.len) then
                            LProtoMapping := 'L2PT';
                        end;

                      {TODO CASE FOR INFO BY PROTOCOL}  
                    end;                  
                  end;
                ETH_P_IPV6 : 
                  begin
                    {IPv6}                       
                    LIPv6Hdr                                                                               := PIPv6Header(LPktData + ETH_HEADER_LEN);
                    LProtoMapping                                                                          := GetIPv6ProtocolName(PIPHeader(LPktData + ETH_HEADER_LEN).Protocol);                    
                    GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1SRC.Index]     := IPv6AddressToString(LIPv6Hdr.SourceAddress);
                    GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1DST.Index]     := IPv6AddressToString(LIPv6Hdr.DestinationAddress); 
                    GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1IPPROTO.Index] := PIPHeader(LPktData + ETH_HEADER_LEN).Protocol                                     
                  end;
              else
                begin
                  LProtoMapping                                                                        := GetEthAcronymName(LEthType);
                  GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1SRC.Index]   := MACAddrToStr(LIPHdr.SrcAddr);
                  GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1DST.Index]   := MACAddrToStr(LIPHdr.DestAddr);
                end;                
              end;

              GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1PROTO.Index] := LProtoMapping;
            end;
          0: 
            begin
              // No packets available at the moment
              Continue;
            end;
          -1: 
            begin
              // Error reading packet
              ShowMessage('Error reading packet: ' + string(pcap_geterr(LHandlePcap)));
              Break;
            end;
          -2:
            begin
              // No packets available, the pcap file instance has been closed
              SetPositionProgressBar(Trunc(cxProgressBar1.Properties.Max));
              Break;
            end;
        end;
      end;
    finally
      // Close PCAP file
      pcap_close(LHandlePcap);
    end;
  Finally
    GridPcapTableView1.DataController.EndUpdate
  End;
end;


procedure TForm2.Button1Click(Sender: TObject);
begin
  if OpenDialog1.Execute then
    OpenPcap(OpenDialog1.FileName);
end;

procedure TForm2.GridPcapTableView1TcxGridDataControllerTcxDataSummaryFooterSummaryItems0GetText(
  Sender: TcxDataSummaryItem; const AValue: Variant; AIsFooter: Boolean;
  var AText: string);
begin
  if VarIsNull(AValue) then Exit;
  
  AText := SizeToStr(AValue)
end;

end.
