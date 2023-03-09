unit UnFormRecording;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, cxGraphics, cxControls, cxLookAndFeels,wpcap.Packet,
  cxLookAndFeelPainters, cxContainer, cxEdit, dxSkinsCore, dxSkinBasic, wpcap.Filter,
  Vcl.Menus, Vcl.StdCtrls, cxButtons, cxGroupBox, cxCheckBox, cxCustomListBox,system.UITypes ,
  cxCheckListBox, cxLabel,wpcap.NetDevice, cxTextEdit,wpcap.DB.SQLite.Packet,wpcap.PCAP,
  cxCustomData, cxStyles, dxScrollbarAnnotations, cxTL, cxTLdxBarBuiltInMenu,System.DateUtils,
  cxInplaceContainer,wpcap.StrUtils, dxToggleSwitch, cxMaskEdit, cxButtonEdit,
  System.ImageList, Vcl.ImgList, cxImageList, cxSpinEdit, Vcl.ExtCtrls,
  dxNavBarCollns, cxClasses, dxNavBarBase, dxNavBar, cxTimeEdit;

type
  TFormRecording = class(TForm)
    SaveDialog1: TSaveDialog;
    cxImageList1: TcxImageList;
    dxNavBar1: TdxNavBar;
    cxGroupBox4: TcxGroupBox;
    cxGroupBox1: TcxGroupBox;
    BCancel: TcxButton;
    BEndRecording: TcxButton;
    BStartRecording: TcxButton;
    cxLabel1: TcxLabel;
    cxGroupBox2: TcxGroupBox;
    EPathDB: TcxButtonEdit;
    cxLabel3: TcxLabel;
    TSfileDumb: TdxToggleSwitch;
    cxGroupBox3: TcxGroupBox;
    cxLabel2: TcxLabel;
    EFilter: TcxTextEdit;
    dxNavBar1Group1: TdxNavBarGroup;
    dxNavBar1Group1Control: TdxNavBarGroupControl;
    cxLabel4: TcxLabel;
    sTimeOutMs: TcxSpinEdit;
    cxLabel5: TcxLabel;
    sMaxSizePacket: TcxSpinEdit;
    ChkEnabledStopRecording: TcxCheckBox;
    tStopRecordingTime: TcxTimeEdit;
    ListInterface: TcxTreeList;
    ListInterfaceColumnNAME: TcxTreeListColumn;
    ListInterfaceColumGUID: TcxTreeListColumn;
    ListInterfaceCOMMENT: TcxTreeListColumn;
    ListInterfaceColumIP: TcxTreeListColumn;
    ListInterfaceColumPROMISC: TcxTreeListColumn;
    procedure FormCreate(Sender: TObject);
    procedure BStartRecordingClick(Sender: TObject);
    procedure EFilterPropertiesValidate(Sender: TObject;
      var DisplayValue: Variant; var ErrorText: TCaption; var Error: Boolean);
    procedure FormDestroy(Sender: TObject);
    procedure BEndRecordingClick(Sender: TObject);
    procedure EPathDBPropertiesButtonClick(Sender: TObject;
      AButtonIndex: Integer);
    procedure ChkEnabledStopRecordingPropertiesEditValueChanged(
      Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
  private
    FTotalSize      : Int64;
    FWPcapDBSqLite  : TWPcapDBSqLitePacket;  
    FCurrentDBName  : String;  
    FPCAPUtils      : TPCAPUtils;
    procedure DoPCAPCallBackError(const aFileName, aError: String);
    procedure DoPCAPCallBackProgress(aTotalSize, aCurrentSize: Int64);
    procedure DoPCAPCallBackPacket(const aInternalPacket: PTInternalPacket);
    procedure DestroyDatabase;
    { Private declarations }
  public
    { Public declarations }
    property CurrentDBName : String read FCurrentDBName;
  end;



implementation

{$R *.dfm}

procedure TFormRecording.FormCreate(Sender: TObject);
var LListInterface : TListCardInterface;
    I              : Integer;
    LCurrentNode: TcxTreeListNode;
begin
  ListInterface.Clear;
  FCurrentDBName             := Format('%sRealtime_%d.db',[ExtractFilePath(Application.ExeName),GetTickCount]);
  EPathDB.Text               := FCurrentDBName;
  SaveDialog1.FileName       := FCurrentDBName;   
  tStopRecordingTime.Enabled := False;
  ModalResult                := mrCancel;
  LListInterface             := GetAdapterList;
  Try
    for I := 0 to LListInterface.Count -1 do 
    begin
      LCurrentNode                := ListInterface.AddChild(nil);
      LCurrentNode.CheckGroupType := ncgRadioGroup;
      LCurrentNode.Values[ListInterfaceColumnNAME.Position.ColIndex]   := LListInterface[I].name;
      LCurrentNode.Values[ListInterfaceColumGUID.Position.ColIndex]    := LListInterface[I].GUID;
      LCurrentNode.Values[ListInterfaceCOMMENT.Position.ColIndex]      := LListInterface[I].description;
      LCurrentNode.Values[ListInterfaceColumIP.Position.ColIndex]      := LListInterface[I].addresses;   
      LCurrentNode.Values[ListInterfaceColumPROMISC.Position.ColIndex] := True;
    end;
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
  Inc(FTotalSize,aCurrentSize);
  cxLabel1.Caption := Format('Captured packet of length %s total size %s',[SizeToStr(aCurrentSize),SizeToStr(FTotalSize)]);
end;

procedure TFormRecording.DoPCAPCallBackPacket(const aInternalPacket: PTInternalPacket);
begin
  if not Assigned(FWPcapDBSqLite) then exit;

  FWPcapDBSqLite.InsertPacket(aInternalPacket);
end;

procedure TFormRecording.BStartRecordingClick(Sender: TObject);
var LIndex       : Integer;
    I            : Integer;
    LStopRecTime : TTime;
begin
  LIndex       := -1;
  LStopRecTime := 0;
  if Not Trim(EFilter.Text).IsEmpty then
  begin
    if not EFilter.ValidateEdit(False) then
    begin
      MessageDlg('Invalid filter',mtWarning,[mbOK],0);      
      Exit;
    end;
  end;


  if Trim(EPathDB.Text).IsEmpty then
  begin
    MessageDlg('Filename is empty',mtWarning,[mbOK],0);      
    Exit;
  end;

  if FileExists(EPathDB.Text) then
  begin  
    if MessageDlg('Database already exists. Continue ?',mtConfirmation,mbYesNo,0) = mrNo then exit;

    DeleteFile(EPathDB.Text);
  end;
  
  
  //TODO recording multi interface
  for I := 0 to ListInterface.AbsoluteCount  -1 do
  begin
    if ListInterface.AbsoluteItems[I].Checked then    
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

  if tStopRecordingTime.Enabled then
    LStopRecTime := tStopRecordingTime.Time;
  
  FCurrentDBName := EPathDB.Text;
  {Create database}
  DestroyDatabase;
  FTotalSize     := 0;
  FWPcapDBSqLite := TWPcapDBSqLitePacket.Create;
  Try

    FWPcapDBSqLite.CreateDatabase(CurrentDBName);
    Try
      BEndRecording.Enabled   := True;
      BStartRecording.Enabled := False;
      BCancel.Enabled         := False;


      {TODO PCAP BY SIZE AND TIME AND END RECORDING DATE}
      if not Assigned(FPCAPUtils) then
        FPCAPUtils := TPCAPUtils.Create;
        
        FPCAPUtils.OnPCAPCallBackError    := DoPCAPCallBackError;
        FPCAPUtils.OnPCAPCallBackProgress := DoPCAPCallBackProgress;
        FPCAPUtils.OnPCAPCallBackPacket   := DoPCAPCallBackPacket;
        FPCAPUtils.OnPCAPCallBackEnd      := nil;                
        FPCAPUtils.AnalyzePCAPRealtime(FCurrentDBName,EFilter.Text,
                                       ListInterface.AbsoluteItems[LIndex].Values[ListInterfaceColumGUID.Position.ColIndex],
                                       ListInterface.AbsoluteItems[LIndex].Values[ListInterfaceColumIP.Position.ColIndex],                                     
                                       ListInterface.AbsoluteItems[LIndex].Values[ListInterfaceColumPROMISC.Position.ColIndex],TSfileDumb.Checked,
                                       sTimeOutMs.Value,sMaxSizePacket.Value,LStopRecTime);          
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
  if Assigned(FPCAPUtils) then
    FreeAndNil(FPCAPUtils);
  DestroyDatabase;
  
end;

procedure TFormRecording.BEndRecordingClick(Sender: TObject);
begin
  BEndRecording.Enabled   := FaLse;
  BStartRecording.Enabled := True;
  BCancel.Enabled         := True;  
  
end;

procedure TFormRecording.EPathDBPropertiesButtonClick(Sender: TObject;
  AButtonIndex: Integer);
begin
  if SaveDialog1.Execute then
    EPathDB.Text := SaveDialog1.FileName;
end;

procedure TFormRecording.ChkEnabledStopRecordingPropertiesEditValueChanged(
  Sender: TObject);
begin
  tStopRecordingTime.Enabled := ChkEnabledStopRecording.Checked;
end;

procedure TFormRecording.FormCloseQuery(Sender: TObject; var CanClose: Boolean);
begin
  if Assigned(FPCAPUtils) then
  begin
    FPCAPUtils.Abort := True;
    while Assigned(FPCAPUtils.ThreadCaptureRT) do
      Application.ProcessMessages;
  end;
end;

end.
