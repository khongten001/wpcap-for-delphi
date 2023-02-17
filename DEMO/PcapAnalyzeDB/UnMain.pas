unit UnMain;

interface
                                                            
uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, 
  Vcl.StdCtrls, cxGraphics, cxControls, cxCustomData, wpcap.Pcap,
  cxGridCustomTableView, cxGridTableView, cxGridLevel, cxClasses,DateUtils,
  cxGrid,  cxLookAndFeels,wpcap.Wrapper,wpcap.Filter,System.Generics.Collections,
  cxLookAndFeelPainters, dxSkinsCore, cxStyles, cxFilter, cxData, cxDataStorage,
  cxEdit, cxNavigator, dxDateRanges, dxScrollbarAnnotations, cxGridCustomView,
  cxContainer, cxProgressBar,wpcap.Pcap.SQLite,wpcap.StrUtils, FireDAC.Stan.Intf,
  FireDAC.Stan.Option, FireDAC.Stan.Error, FireDAC.UI.Intf, FireDAC.Phys.Intf,
  FireDAC.Stan.Def, FireDAC.Stan.Pool, FireDAC.Stan.Async, FireDAC.Phys,
  FireDAC.VCLUI.Wait, FireDAC.Stan.Param, FireDAC.DatS, FireDAC.DApt.Intf,
  FireDAC.DApt, FireDAC.Stan.ExprFuncs, FireDAC.Phys.SQLiteWrapper.Stat,
  FireDAC.Phys.SQLiteDef, Data.DB, cxDBData, cxGridDBTableView, wpcap.DB.SQLite,
  FireDAC.Phys.SQLite, FireDAC.Comp.DataSet, FireDAC.Comp.Client,
  FireDAC.Comp.ScriptCommands, FireDAC.Stan.Util, FireDAC.Comp.Script,
  cxTextEdit, cxMemo, cxSplitter, dxBar, System.ImageList, Vcl.ImgList,
  cxImageList, dxSkinBasic, dxCore, dxSkinsForm, cxLabel, cxGroupBox;

type
  TFormMain = class(TForm)
    OpenDialog1: TOpenDialog;
    GridPcapLevel1: TcxGridLevel;
    GridPcap: TcxGrid;
    cxProgressBar1: TcxProgressBar;
    GridPcapDBTableView1: TcxGridDBTableView;
    DsGrid: TDataSource;
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
    cxSplitter1: TcxSplitter;
    MemoHex: TcxMemo;
    dxBarManager1: TdxBarManager;
    dxBarManager1Bar1: TdxBar;
    BSavePCAP: TdxBarButton;
    BLoadPCAP: TdxBarButton;
    cxImageList1: TcxImageList;
    SaveDialog1: TSaveDialog;
    dxSkinController1: TdxSkinController;
    cxGroupBox1: TcxGroupBox;
    cxLabel1: TcxLabel;
    EFilter: TcxTextEdit;
    BStartRecording: TdxBarButton;
    procedure GridPcapTableView1TcxGridDataControllerTcxDataSummaryFooterSummaryItems0GetText(
      Sender: TcxDataSummaryItem; const AValue: Variant; AIsFooter: Boolean;
      var AText: string);
    procedure EFilterPropertiesValidate(Sender: TObject;
      var DisplayValue: Variant; var ErrorText: TCaption; var Error: Boolean);
    procedure GridPcapDBTableView1FocusedRecordChanged(
      Sender: TcxCustomGridTableView; APrevFocusedRecord,
      AFocusedRecord: TcxCustomGridRecord;
      ANewItemRecordFocusingChanged: Boolean);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure BLoadPCAPClick(Sender: TObject);
    procedure BSavePCAPClick(Sender: TObject);
    procedure BStartRecordingClick(Sender: TObject);
  private
    { Private declarations }
    FWPcapDBSqLite : TWPcapDBSqLite;
    FPCAPUtils     : TPCAPUtils;
    procedure OpenPcap(const aFileName: String);
    procedure SetPositionProgressBar(aNewPos: Int64);
    procedure DoPCAPOfflineCallBackEnd(const aFileName: String);
    procedure DoPCAPOfflineCallBackError(const aFileName, aError: String);
    procedure DoPCAPOfflineCallBackProgress(aTotalSize, aCurrentSize: Int64);
  public
    { Public declarations }
  end;

var
  FormMain: TFormMain;

implementation

uses UnFormRecording;

{$R *.dfm}

Procedure TFormMain.SetPositionProgressBar(aNewPos : Int64);
begin
  cxProgressBar1.Position := aNewPos;
  if Trunc( (aNewPos * 100) / cxProgressBar1.Properties.Max) Mod 5 = 0 then                
    cxProgressBar1.Update
end;
                                                                                                  
procedure TFormMain.DoPCAPOfflineCallBackError(const aFileName,aError:String);
begin
  MessageDlg(Format('PCAP %s Error %s',[aFileName,aError]),mtError,[mbOK],0);
end;

procedure TFormMain.DoPCAPOfflineCallBackProgress(aTotalSize,aCurrentSize:Int64);
begin
  cxProgressBar1.Properties.Max := aTotalSize; 
  SetPositionProgressBar(aCurrentSize);
end;

procedure TFormMain.DoPCAPOfflineCallBackEnd(const aFileName:String);
begin
 MessageDlg(Format('PCAP %s analyze compleate',[aFileName]),mtInformation,[mbOK],0);

  FWPcapDBSqLite.OpenDatabase(ChangeFileExt(aFileName,'.db'));

  if FWPcapDBSqLite.Connection.Connected then  
  begin
    DsGrid.DataSet := FWPcapDBSqLite.FDQueryGrid;
    FWPcapDBSqLite.FDQueryGrid.Open;
  end;
end;

procedure TFormMain.OpenPcap(const aFileName:String);
begin
  Caption := Format('PCAP Analisys %s - %s',[ExtractFileName(aFileName),PacketGetVersion]);
  FWPcapDBSqLite.Connection.Close;
  FWPcapDBSqLite.FDQueryGrid.Close;
  SetPositionProgressBar(0);
  
  {TODO 
    Thread with syncronize
    Query bulder 
    Packet detail [TreeView Like wireshark with syncronize with memo ???? HOW ?]
    TcpFlow 
    UdpFlow
    ChartStatistics by protocol
    Grid with port
    Color for grid
      
  }
  // filter example dst host 192.0.2.1 but doesn't work  TODO check structure and function definition
  DeleteFile(ChangeFileExt(aFileName,'.db'));
  if Not Trim(EFilter.Text).IsEmpty then
  begin
    if not EFilter.ValidateEdit(False) then
    begin
      MessageDlg('Invalid filter',mtWarning,[mbOK],0);
      Exit;
    end;
  end;
    
  TPCAP2SQLite.PCAP2SQLite(aFileName,ChangeFileExt(aFileName,'.db'),EFilter.Text,DoPCAPOfflineCallBackError,DoPCAPOfflineCallBackEnd,DoPCAPOfflineCallBackProgress);
end;

procedure TFormMain.GridPcapTableView1TcxGridDataControllerTcxDataSummaryFooterSummaryItems0GetText(
  Sender: TcxDataSummaryItem; const AValue: Variant; AIsFooter: Boolean;
  var AText: string);
begin
  if VarIsNull(AValue) then Exit;
  
  AText := SizeToStr(AValue)
end;

procedure TFormMain.EFilterPropertiesValidate(Sender: TObject;
  var DisplayValue: Variant; var ErrorText: TCaption; var Error: Boolean);
begin
   if VarIsNull(DisplayValue) then Exit;

   if not ValidateWinPCAPFilterExpression(DisplayValue) then
   begin
      ErrorText := 'Invalid filter';
      Error     := True;
   end;    
end;

procedure TFormMain.GridPcapDBTableView1FocusedRecordChanged(
  Sender: TcxCustomGridTableView; APrevFocusedRecord,
  AFocusedRecord: TcxCustomGridRecord; ANewItemRecordFocusingChanged: Boolean);
var LHexList : TArray<String>;
    I        : Integer;
begin
  MemoHex.Lines.Clear;
  if Assigned(AFocusedRecord) then
  begin
     LHexList := FWPcapDBSqLite.GetListHexPacket(AFocusedRecord.Values[GridPcapDBTableView1NPACKET.Index]);
     for I := Low(LHexList) to High(LHexList) do
      MemoHex.Lines.Add(LHexList[I]);     
  end;  
end;

procedure TFormMain.FormCreate(Sender: TObject);
begin
  MemoHex.Style.Font.Name := 'Courier New';
  MemoHex.Style.Font.Size := 10;
  FWPcapDBSqLite          := TWPcapDBSqLite.Create;
end;

procedure TFormMain.FormDestroy(Sender: TObject);
begin
  FreeAndNil(FWPcapDBSqLite);
end;

procedure TFormMain.BLoadPCAPClick(Sender: TObject);
begin
  if OpenDialog1.Execute then
    OpenPcap(OpenDialog1.FileName);
end;

procedure TFormMain.BSavePCAPClick(Sender: TObject);
var I                : Integer;
    LListPacket      : TList<PTPacketToDump>;
    LPacket          : PByte;
    LPcketSize       : Integer;
    LPacketToDump    : PTPacketToDump;
begin
  if SaveDialog1.Execute then
  begin
    LListPacket := TList<PTPacketToDump>.Create;
    Try
      for I := 0 to GridPcapDBTableView1.DataController.RecordCount -1 do
      begin
        LPacket := FWPcapDBSqLite.GetPacketDataFromDatabase(GridPcapDBTableView1.DataController.Values[I,GridPcapDBTableView1NPACKET.Index],LPcketSize);
        if Assigned(LPacket) then
        begin
          New(LPacketToDump);
          LPacketToDump.PacketLen := LPcketSize;
          LPacketToDump.packet    := LPacket;
          LPacketToDump.tv_sec    := DateTimeToUnix(StrToDateTime(GridPcapDBTableView1.DataController.Values[I,GridPcapDBTableView1PACKET_DATE.Index]),False);            
          LListPacket.Add(LPacketToDump);        
        end;
      end;

      if LListPacket.Count > 0 then
        FPCAPUtils.SavePacketListToPcapFile(LListPacket,SaveDialog1.FileName);      
    Finally
      FreeAndNil(LListPacket);
    End;
  end;
end;

procedure TFormMain.BStartRecordingClick(Sender: TObject);
var aFormRecording: TFormRecording;
begin
   aFormRecording := TFormRecording.Create(nil);
   Try   
      aFormRecording.ShowModal;
      if aFormRecording.ModalResult = mrOK then
      begin
      
      end;
      
   Finally
     FreeAndNil(aFormRecording);
   End;
end;

end.
