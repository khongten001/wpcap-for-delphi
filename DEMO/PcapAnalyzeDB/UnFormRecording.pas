unit UnFormRecording;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, cxGraphics, cxControls, cxLookAndFeels,wpcap.Packet,
  cxLookAndFeelPainters, cxContainer, cxEdit, dxSkinsCore, dxSkinBasic, wpcap.Filter,
  Vcl.Menus, Vcl.StdCtrls, cxButtons, cxGroupBox, cxCheckBox, cxCustomListBox,system.UITypes ,
  cxCheckListBox, cxLabel,wpcap.NetDevice, cxTextEdit,wpcap.DB.SQLite,wpcap.PCAP,
  cxCustomData, cxStyles, dxScrollbarAnnotations, cxTL, cxTLdxBarBuiltInMenu,
  cxInplaceContainer,wpcap.StrUtils, dxToggleSwitch, cxMaskEdit, cxButtonEdit,
  System.ImageList, Vcl.ImgList, cxImageList;

type
  TFormRecording = class(TForm)
    cxGroupBox1: TcxGroupBox;
    cxGroupBox2: TcxGroupBox;
    BCancel: TcxButton;
    BEndRecording: TcxButton;
    BStartRecording: TcxButton;
    cxLabel1: TcxLabel;
    cxGroupBox3: TcxGroupBox;
    cxLabel2: TcxLabel;
    EFilter: TcxTextEdit;
    ListInterface: TcxTreeList;
    ListInterfaceColumGUID: TcxTreeListColumn;
    ListInterfaceCOMMENT: TcxTreeListColumn;
    ListInterfaceColumPROMISC: TcxTreeListColumn;
    ListInterfaceColumIP: TcxTreeListColumn;
    EPathDB: TcxButtonEdit;
    cxLabel3: TcxLabel;
    TSfileDumb: TdxToggleSwitch;
    SaveDialog1: TSaveDialog;
    cxImageList1: TcxImageList;
    ListInterfaceColumnNAME: TcxTreeListColumn;
    procedure FormCreate(Sender: TObject);
    procedure BStartRecordingClick(Sender: TObject);
    procedure EFilterPropertiesValidate(Sender: TObject;
      var DisplayValue: Variant; var ErrorText: TCaption; var Error: Boolean);
    procedure FormDestroy(Sender: TObject);
    procedure BEndRecordingClick(Sender: TObject);
    procedure EPathDBPropertiesButtonClick(Sender: TObject;
      AButtonIndex: Integer);
  private
    FTotalSize      : Int64;
    FWPcapDBSqLite  : TWPcapDBSqLite;  
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
  FCurrentDBName        := Format('%sRealtime_%d.db',[ExtractFilePath(Application.ExeName),GetTickCount]);
  EPathDB.Text          := FCurrentDBName;
  SaveDialog1.FileName  := FCurrentDBName;   
  ModalResult           := mrCancel;
  LListInterface        := GetAdapterList;
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
  FWPcapDBSqLite.InsertPacket(aInternalPacket);
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


  if Trim(EPathDB.Text  ).IsEmpty then
  begin
    MessageDlg('Filename is empty',mtWarning,[mbOK],0);      
    Exit;
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
  
  FCurrentDBName := EPathDB.Text;
  {Create database}
  DestroyDatabase;
  FTotalSize     := 0;
  FWPcapDBSqLite := TWPcapDBSqLite.Create;
  Try

    FWPcapDBSqLite.CreateDatabase(CurrentDBName);
    Try
      BEndRecording.Enabled   := True;
      BStartRecording.Enabled := False;
      BCancel.Enabled         := False;

      {TODO PCAP BY SIZE AND TIME AND END RECORDING DATE}
      FPCAPUtils := TPCAPUtils.Create;
      Try
        FPCAPUtils.AnalyzePCAPRealtime(FCurrentDBName,EFilter.Text,
                                       ListInterface.AbsoluteItems[LIndex].Values[ListInterfaceColumGUID.Position.ColIndex],
                                       ListInterface.AbsoluteItems[LIndex].Values[ListInterfaceColumIP.Position.ColIndex],                                     
                                       ListInterface.AbsoluteItems[LIndex].Values[ListInterfaceColumPROMISC.Position.ColIndex],TSfileDumb.Checked,
                                       DoPCAPCallBackPacket,DoPCAPCallBackError,DoPCAPCallBackProgress);          
      Finally
        FreeAndNil(FPCAPUtils);
      End;
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

procedure TFormRecording.EPathDBPropertiesButtonClick(Sender: TObject;
  AButtonIndex: Integer);
begin
  if SaveDialog1.Execute then
    EPathDB.Text := SaveDialog1.FileName;
end;

end.
