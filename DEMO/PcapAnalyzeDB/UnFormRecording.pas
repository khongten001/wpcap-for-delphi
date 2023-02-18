unit UnFormRecording;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, cxGraphics, cxControls, cxLookAndFeels,
  cxLookAndFeelPainters, cxContainer, cxEdit, dxSkinsCore, dxSkinBasic, wpcap.Filter,
  Vcl.Menus, Vcl.StdCtrls, cxButtons, cxGroupBox, cxCheckBox, cxCustomListBox,
  cxCheckListBox, cxLabel,wpcap.NetDevice, cxTextEdit,wpcap.DB.SQLite,wpcap.PCAP;

type
  TFormRecording = class(TForm)
    cxGroupBox1: TcxGroupBox;
    cxGroupBox2: TcxGroupBox;
    BCancel: TcxButton;
    BEndRecording: TcxButton;
    BStartRecording: TcxButton;
    cxLabel1: TcxLabel;
    ListInterface: TcxCheckListBox;
    cxGroupBox3: TcxGroupBox;
    cxLabel2: TcxLabel;
    EFilter: TcxTextEdit;
    procedure FormCreate(Sender: TObject);
    procedure BStartRecordingClick(Sender: TObject);
    procedure EFilterPropertiesValidate(Sender: TObject;
      var DisplayValue: Variant; var ErrorText: TCaption; var Error: Boolean);
    procedure FormDestroy(Sender: TObject);
    procedure BEndRecordingClick(Sender: TObject);
  private
    FTotalSize      : Int64;
    FWPcapDBSqLite  : TWPcapDBSqLite;  
    FCurrentDBName  : String;  
    FPCAPUtils      : TPCAPUtils;
    procedure DoPCAPCallBackError(const aFileName, aError: String);
    procedure DoPCAPCallBackProgress(aTotalSize, aCurrentSize: Int64);
    procedure DoPCAPCallBackPacket(const aPktData: PByte; aPktLen: LongWord;
      aPktDate: TDateTime; aEthType: Word; const atEthAcronym, aMacSrc,
      aMacDst: String; aIPProto: Word; const aIPProtoMapping, aIpSrc,
      aIpDst: String; aPortSrc, aPortDst: Word;aIdProtoDetected:byte);
    procedure DestroyDatabase;
    { Private declarations }
  public
    { Public declarations }
    property CurrentDBName : String read FCurrentDBName;
  end;



implementation

{$R *.dfm}

procedure TFormRecording.FormCreate(Sender: TObject);
var LListInterface : TStringList;
    I              : Integer;
begin
  ModalResult    := mrCancel;
  LListInterface := GetAdapterList;
  Try
    for I := 0 to LListInterface.Count -1 do 
      ListInterface.Items.Add.Text := LListInterface[I];  
  Finally
    FreeAndNil(LListInterface);
  End;
end;

procedure TFormRecording.DoPCAPCallBackError(const aFileName,aError:String);
begin
  MessageDlg(Format('Recording %s Error %s',[aFileName,aError]),mtError,[mbOK],0);
  BEndRecording.Enabled   := False;
  BCancel.Enabled         := True;  
  BStartRecording.Enabled := True;  
end;

procedure TFormRecording.DoPCAPCallBackProgress(aTotalSize,aCurrentSize:Int64);
begin
  FTotalSize       := aCurrentSize;
  cxLabel1.Caption := Format('Captured packet of length %d total size %d',[aCurrentSize,FTotalSize]);
end;

procedure TFormRecording.DoPCAPCallBackPacket(  const aPktData:PByte;aPktLen:LongWord;aPktDate:TDateTime;//Packet info
                                                aEthType:Word;const atEthAcronym,aMacSrc,aMacDst:String; // Eth info
                                                aIPProto:Word;const aIPProtoMapping,aIpSrc,aIpDst:String;aPortSrc,aPortDst:Word;aIdProtoDetected:byte);
begin
  FWPcapDBSqLite.InsertPacket(aPktData,aPktLen,aPktDate,aEthType,atEthAcronym, aMacSrc, aMacDst,aIPProto,aIPProtoMapping, aIpSrc, aIpDst,aPortSrc, aPortDst,aIdProtoDetected);
end;


procedure TFormRecording.BStartRecordingClick(Sender: TObject);
var LIndex : Integer;
    I      : Integer;
begin
  LIndex := -1;
  if Not Trim(EFilter.Text).IsEmpty then
  begin
    if not EFilter.ValidateEdit(False) then
    begin
      MessageDlg('Invalid filter',mtWarning,[mbOK],0);
      Exit;
    end;
  end;
  
  //TODO recording multi interface
  for I := 0 to ListInterface.Items.Count -1 do
  begin
    if ListInterface.Items[I].Checked then    
    begin
      LIndex := I;
      Break;
    end;
  end;

  if LIndex = -1 then
  begin
    MessageDlg('Select one interface',mtWarning,[mbOK],0);
    Exit;
  end;

  {Create database}
  DestroyDatabase;
  FWPcapDBSqLite := TWPcapDBSqLite.Create;
  Try
    FCurrentDBName := Format('%sRealtime_%d.db',[ExtractFilePath(Application.ExeName),GetTickCount]);
    FWPcapDBSqLite.CreateDatabase(CurrentDBName);
    Try
      BEndRecording.Enabled   := True;
      BStartRecording.Enabled := False;
      BCancel.Enabled         := False;
      FPCAPUtils.AnalyzePCAPRealtime(FCurrentDBName,EFilter.Text,ListInterface.Items[LIndex].Text,DoPCAPCallBackPacket,DoPCAPCallBackError,DoPCAPCallBackProgress);          
    except on E: Exception do
      DoPCAPCallBackError(CurrentDBName,Format('Exception analyze PCAP %s',[E.Message]));
    end;    
  except on E: Exception do
    DoPCAPCallBackError(CurrentDBName,Format('Exception create database %s',[E.Message]));
  end;    
end;



procedure TFormRecording.DestroyDatabase;
begin
   if Assigned(FWPcapDBSqLite) then
    FreeAndNil(FWPcapDBSqLite); 
end;

procedure TFormRecording.EFilterPropertiesValidate(Sender: TObject;
  var DisplayValue: Variant; var ErrorText: TCaption; var Error: Boolean);
begin
   if VarIsNull(DisplayValue) then Exit;

   if not ValidateWinPCAPFilterExpression(DisplayValue) then
   begin
      ErrorText := 'Invalid filter';
      Error     := True;
   end;    
end;

procedure TFormRecording.FormDestroy(Sender: TObject);
begin
  DestroyDatabase;
end;

procedure TFormRecording.BEndRecordingClick(Sender: TObject);
begin
  FPCAPUtils.StopAnalyze;
      BEndRecording.Enabled   := FaLse;
      BStartRecording.Enabled := True;
      BCancel.Enabled         := True;  
end;

end.
