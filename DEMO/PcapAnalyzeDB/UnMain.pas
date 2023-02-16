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
  cxContainer, cxProgressBar,wpcap.Offline.SQLite,wpcap.StrUtils, FireDAC.Stan.Intf,
  FireDAC.Stan.Option, FireDAC.Stan.Error, FireDAC.UI.Intf, FireDAC.Phys.Intf,
  FireDAC.Stan.Def, FireDAC.Stan.Pool, FireDAC.Stan.Async, FireDAC.Phys,
  FireDAC.VCLUI.Wait, FireDAC.Stan.Param, FireDAC.DatS, FireDAC.DApt.Intf,
  FireDAC.DApt, FireDAC.Stan.ExprFuncs, FireDAC.Phys.SQLiteWrapper.Stat,
  FireDAC.Phys.SQLiteDef, Data.DB, cxDBData, cxGridDBTableView,
  FireDAC.Phys.SQLite, FireDAC.Comp.DataSet, FireDAC.Comp.Client,
  FireDAC.Comp.ScriptCommands, FireDAC.Stan.Util, FireDAC.Comp.Script;

type
  TForm2 = class(TForm)
    Button1: TButton;
    OpenDialog1: TOpenDialog;
    GridPcapLevel1: TcxGridLevel;
    GridPcap: TcxGrid;
    cxProgressBar1: TcxProgressBar;
    FDConnection1: TFDConnection;
    FDGrid: TFDQuery;
    FDPhysSQLiteDriverLink1: TFDPhysSQLiteDriverLink;
    GridPcapDBTableView1: TcxGridDBTableView;
    DsGrid: TDataSource;
    FDScript1: TFDScript;
    FDGridNPACKET: TFDAutoIncField;
    FDGridPACKET_LEN: TIntegerField;
    FDGridPACKET_DATE: TWideMemoField;
    FDGridETH_TYPE: TIntegerField;
    FDGridETH_ACRONYM: TWideMemoField;
    FDGridMAC_SRC: TWideMemoField;
    FDGridMAC_DST: TWideMemoField;
    FDGridIPPROTO: TIntegerField;
    FDGridPROTOCOL: TWideMemoField;
    FDGridIP_SRC: TWideMemoField;
    FDGridIP_DST: TWideMemoField;
    FDGridPORT_SRC: TIntegerField;
    FDGridPORT_DST: TLargeintField;
    FDGridPACKET_DATA: TBlobField;
    GridPcapDBTableView1NPACKET: TcxGridDBColumn;
    GridPcapDBTableView1PACKET_LEN: TcxGridDBColumn;
    GridPcapDBTableView1PACKET_DATE: TcxGridDBColumn;
    GridPcapDBTableView1ETH_TYPE: TcxGridDBColumn;
    GridPcapDBTableView1ETH_ACRONYM: TcxGridDBColumn;
    GridPcapDBTableView1MAC_SRC: TcxGridDBColumn;
    GridPcapDBTableView1MAC_DST: TcxGridDBColumn;
    GridPcapDBTableView1IPPROTO: TcxGridDBColumn;
    GridPcapDBTableView1PROTOCOL: TcxGridDBColumn;
    GridPcapDBTableView1IP_SRC: TcxGridDBColumn;
    GridPcapDBTableView1IP_DST: TcxGridDBColumn;
    GridPcapDBTableView1PORT_SRC: TcxGridDBColumn;
    GridPcapDBTableView1PORT_DST: TcxGridDBColumn;
    procedure Button1Click(Sender: TObject);
    procedure GridPcapTableView1TcxGridDataControllerTcxDataSummaryFooterSummaryItems0GetText(
      Sender: TcxDataSummaryItem; const AValue: Variant; AIsFooter: Boolean;
      var AText: string);
  private
    procedure OpenPcap(const aFileName: String);
    procedure SetPositionProgressBar(aNewPos: Int64);
    procedure DoPCAPOfflineCallBackEnd(const aFileName: String);
    procedure DoPCAPOfflineCallBackError(const aFileName, aError: String);
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
                                                                                                  
procedure TForm2.DoPCAPOfflineCallBackError(const aFileName,aError:String);
begin
 ShowMessageFmt('PCAP %s Error %s',[aFileName,aError]);
end;

procedure TForm2.DoPCAPOfflineCallBackProgress(aTotalSize,aCurrentSize:Int64);
begin
  cxProgressBar1.Properties.Max := aTotalSize; 
  SetPositionProgressBar(aCurrentSize);
end;


procedure TForm2.DoPCAPOfflineCallBackEnd(const aFileName:String);
begin
  ShowMessageFmt('PCAP %s analyze compleate',[aFileName]);
  FDConnection1.Params.Values['DriverID'] := 'SQLite';
  FDConnection1.Params.Values['Database'] := ChangeFileExt(aFileName,'.db');
  FDConnection1.Connected := True;
  FDGrid.Open;

end;


procedure TForm2.OpenPcap(const aFileName:String);
begin
  Caption := Format('PCAP Analisys %s',[ExtractFileName(aFileName)]);
  FDConnection1.Close;
  FDGrid.Close;
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
  TPCAP2SQLite.PCAP2SQLite(aFileName,ChangeFileExt(aFileName,'.db'),DoPCAPOfflineCallBackError,DoPCAPOfflineCallBackEnd,DoPCAPOfflineCallBackProgress);
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
