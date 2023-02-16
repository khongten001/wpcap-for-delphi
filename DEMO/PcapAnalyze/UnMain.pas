unit UnMain;

interface
                                                            
uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, 
  Vcl.StdCtrls, cxGraphics, cxControls, cxCustomData, 
  cxGridCustomTableView, cxGridTableView, cxGridLevel, cxClasses,
  cxGrid,  cxLookAndFeels,
  cxLookAndFeelPainters, dxSkinsCore, cxStyles, cxFilter, cxData, cxDataStorage,
  cxEdit, cxNavigator, dxDateRanges, dxScrollbarAnnotations, cxGridCustomView,
  cxContainer, cxProgressBar,wpcap.Offline,wpcap.StrUtils;

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
    procedure DoPCAPOfflineCallBackEnd(const aFileName: String);
    procedure DoPCAPOfflineCallBackError(const aFileName, aError: String);
    procedure DoPCAPOfflineCallBackPacket(const aPktData: PByte;
      aPktLen: LongWord; aPktDate: TDateTime; aEthType: Word;
      const atEthAcronym, aMacSrc, aMacDst: String; LaPProto: Word;
      const aIPProtoMapping, aIpSrc, aIpDst: String; aPortSrc, aPortDst: Word);
    procedure DoPCAPOfflineCallBackProgress(aTotalSize, aCurrentSize: Int64);
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

procedure TForm2.DoPCAPOfflineCallBackPacket(  const aPktData:PByte;aPktLen:LongWord;aPktDate:TDateTime;//Packet info
                                                aEthType:Word;const atEthAcronym,aMacSrc,aMacDst:String; // Eth info
                                                LaPProto:Word;const aIPProtoMapping,aIpSrc,aIpDst:String;aPortSrc,aPortDst:Word  );
var LIndexPacket : integer;                                                
begin 
  LIndexPacket := GridPcapTableView1.DataController.AppendRecord;
  
  {Common packet info}
  GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1COUNT.Index]       := LIndexPacket+1;
  GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1LEN.Index]         := aPktLen;
  GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1DATA.Index]        := aPktDate;
  GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1ETHTYPE.Index]     := atEthAcronym;
  GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1ETHTYPENUM.Index]  := aEthType;
  GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1MACSrc.Index]      := aMacSrc;
  GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1MacDst.Index]      := aMacDst;
  GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1SRC.Index]         := aIpSrc;
  GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1DST.Index]         := aIpDst;
  GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1IPPROTO.Index]     := LaPProto;
  GridPcapTableView1.DataController.Values[LIndexPacket,GridPcapTableView1PROTO.Index]       := aIPProtoMapping;  
end;
                                                
                                                  
procedure TForm2.DoPCAPOfflineCallBackError(const aFileName,aError:String);
begin
 ShowMessageFmt('PCAP %s Error %s',[aFileName,aError]);
 GridPcapTableView1.DataController.EndUpdate;
end;

procedure TForm2.DoPCAPOfflineCallBackProgress(aTotalSize,aCurrentSize:Int64);
begin
  cxProgressBar1.Properties.Max := aTotalSize; 
  SetPositionProgressBar(aCurrentSize);
end;


procedure TForm2.DoPCAPOfflineCallBackEnd(const aFileName:String);
begin
  ShowMessageFmt('PCAP %s analyze compleate',[aFileName]);
  GridPcapTableView1.DataController.EndUpdate;
end;


procedure TForm2.OpenPcap(const aFileName:String);
begin
  Caption := Format('PCAP Analisys %s',[ExtractFileName(aFileName)]);
  GridPcapTableView1.DataController.RecordCount := 0;
  GridPcapTableView1.DataController.BeginUpdate;
  SetPositionProgressBar(0);
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
      Color for grid
      
    }
  AnalyzePCAPOffline(aFileName,String.Empty,DoPCAPOfflineCallBackPacket,DoPCAPOfflineCallBackError,DoPCAPOfflineCallBackEnd,DoPCAPOfflineCallBackProgress);
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
