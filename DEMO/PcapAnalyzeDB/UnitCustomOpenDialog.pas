unit UnitCustomOpenDialog;

interface

uses
  WinApi.Windows, dxForms, WinApi.Messages, System.SysUtils, system.UiTypes,
  System.Variants, System.Classes, Vcl.Graphics, vcl.Controls, vcl.Forms,
  vcl.Dialogs, cxGraphics, cxControls, cxLookAndFeels, cxLookAndFeelPainters,
  cxContainer, cxEdit, dxSkinsCore, dxSkinBasic, Vcl.Menus, Vcl.ComCtrls,
  Winapi.ShlObj, cxShellCommon, Vcl.ExtCtrls, cxTreeView, cxShellTreeView,
  cxListView, cxShellListView, cxSplitter, cxTextEdit, cxMaskEdit, cxButtonEdit,
  dxBreadcrumbEdit, dxShellBreadcrumbEdit, Vcl.StdCtrls, cxButtons, cxGroupBox,
  cxLabel, System.ImageList, Vcl.ImgList, cxImageList;

type
  TFormOpenDialog = Class(TDxForm)
    pnlButtonBottom: TcxGroupBox;
    BCancel: TcxButton;
    BImport: TcxButton;
    cxShellListView1: TcxShellListView;
    cxGroupBox2: TcxGroupBox;
    dxShellBreadcrumbEdit1: TdxShellBreadcrumbEdit;
    BBack: TcxButton;
    cxShellTreeView1: TcxShellTreeView;
    cxSplitter1: TcxSplitter;
    ESearch: TcxButtonEdit;
    cxSplitter2: TcxSplitter;
    TimerSearch: TTimer;
    cxGroupBox1: TcxGroupBox;
    cxGroupBox3: TcxGroupBox;
    cxLabel2: TcxLabel;
    EFilter: TcxTextEdit;
    cxImageList1: TcxImageList;
    procedure btnAnnullaClick(Sender: TObject);
    procedure cxShellListView1CurrentFolderChanged(
      Sender: TcxCustomShellListView);
    procedure cxShellListView1MouseUp(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure FormShow(Sender: TObject);
    procedure BBackClick(Sender: TObject);
    procedure cxShellTreeView1MouseUp(Sender: TObject; Button: TMouseButton;
      Shift: TShiftState; X, Y: Integer);
    procedure dxShellBreadcrumbEdit1PathSelected(Sender: TObject);
    procedure TimerSearchTimer(Sender: TObject);
    procedure BImportClick(Sender: TObject);
    procedure ESearchPropertiesEditValueChanged(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
    procedure ESearchKeyPress(Sender: TObject; var Key: Char);
    procedure cxShellListView1AddFolder(Sender: TObject;
      AFolder: TcxShellFolder; var ACanAdd: Boolean);
    procedure cxShellListView1KeyDown(Sender: TObject; var Key: Word;
      Shift: TShiftState);
    procedure cxShellListView1DblClick(Sender: TObject);
    procedure EFilterPropertiesValidate(Sender: TObject;
      var DisplayValue: Variant; var ErrorText: TCaption; var Error: Boolean);
  private
    { Private declarations }
    CONST FILE_MASK = '*.pcap;*.raw;*.pcapng';
    var
    FWidthColumn0              : Integer;
    FWidthColumn1              : Integer;
    FWidthColumn2              : Integer;
    FWidthColumn3              : Integer;
    FFilename                  : String;    
    function GetInitialDir: String;
    procedure SetInitialDir(const Value: String);
    procedure SaveColumnStatus;
    procedure ResetSearch;  
    procedure RestoreColumns;
  public
    { Public declarations }
    property Filename                 : String          read FFilename                 write FFilename;
    property InitialDir               : String          read GetInitialDir             write SetInitialDir;
  end;


implementation

uses wpcap.Filter;

{$R *.dfm}

procedure TFormOpenDialog.ResetSearch;
begin
  ESearch.Text                      := String.Empty;
  TimerSearch.Enabled               := False;
  cxShellListView1.Options.FileMask := FILE_MASK;
end;

procedure TFormOpenDialog.BImportClick(Sender: TObject);
var AItem    : TListItem;
begin
  if Not Trim(EFilter.Text).IsEmpty then
  begin
    if not EFilter.ValidateEdit(False) then
    begin
      MessageDlg('Invalid filter',mtWarning,[mbOK],0);
      Exit;
    end;
  end;

  if cxShellListView1.SelectedFilePaths.count > 0 then
  begin
    AItem    := cxShellListView1.InnerListView.Selected;
    
    if Assigned(AItem) then
    begin
      if cxShellListView1.Folders[AItem.Index].IsFolder then  
      begin
        MessageBox(Handle, Pchar('No selected files'), PChar('Warning'), MB_ICONWARNING or MB_OK );
        Exit;
      end;      

      FFilename := cxShellListView1.Folders[AItem.Index].PathName;   
    end;
    
    ModalResult := mrOK;
    CloseModal;
  end
  else
    MessageBox(Handle, Pchar('No selected files'), PChar('Warning'), MB_ICONWARNING or MB_OK );

end;

procedure TFormOpenDialog.btnAnnullaClick(Sender: TObject);
begin
  ModalResult := mrCancel;
  CloseModal;
end;

procedure TFormOpenDialog.BBackClick(Sender: TObject);
begin
  SaveColumnStatus;
  cxShellListView1.BrowseParent;
end;

procedure TFormOpenDialog.cxShellListView1AddFolder(Sender: TObject;
  AFolder: TcxShellFolder; var ACanAdd: Boolean);
begin
  if ACanAdd  then
  begin
    if Not AFolder.IsFolder  then
    begin
      if ExtractFileExt(AFolder.PathName) <> '' then
        ACanAdd := Pos(LowerCase(ExtractFileExt(AFolder.PathName)),LowerCase(FILE_MASK)) > 0
    end
    else if ExtractFileExt(AFolder.PathName) <> '' then
      ACanAdd := Not SameText(ExtractFileExt(AFolder.PathName), '.zip');
  end;
end;

procedure TFormOpenDialog.RestoreColumns;
var I: Integer;
begin
  for I := 0 to cxShellListView1.InnerListView.Columns.Count - 1 do
  begin
    case I of
      0 : cxShellListView1.InnerListView.Columns[I].Width := FWidthColumn0;
      1 : cxShellListView1.InnerListView.Columns[I].Width := FWidthColumn1;
      2 : cxShellListView1.InnerListView.Columns[I].Width := FWidthColumn2;
      3 : cxShellListView1.InnerListView.Columns[I].Width := FWidthColumn3;
    else
      Break;
    end;
  end;
end;

procedure TFormOpenDialog.cxShellListView1CurrentFolderChanged(
  Sender: TcxCustomShellListView);
begin
  RestoreColumns;
  ResetSearch;
end;

procedure TFormOpenDialog.cxShellListView1DblClick(Sender: TObject);
begin
  if cxShellListView1.SelectedFilePaths.Count = 1 then
  begin
    if pnlButtonBottom.Visible then
    begin
      if FileExists(cxShellListView1.SelectedFilePaths[0]) then
        BImportClick(BImport);
    end;
  end;
end;

procedure TFormOpenDialog.cxShellListView1KeyDown(Sender: TObject;
  var Key: Word; Shift: TShiftState);
begin
  if Shift = [ssCtrl] then
    if Key = ord('A') then
      cxShellListView1.InnerListView.SelectAll;
end;

Procedure TFormOpenDialog.SaveColumnStatus;
var I : Integer;
begin
  for I := 0 to cxShellListView1.InnerListView.Columns.Count - 1 do
  begin
    case I of
      0 : FWidthColumn0 := cxShellListView1.InnerListView.Columns[I].Width;
      1 : FWidthColumn1 := cxShellListView1.InnerListView.Columns[I].Width;
      2 : FWidthColumn2 := cxShellListView1.InnerListView.Columns[I].Width;
      3 : FWidthColumn3 := cxShellListView1.InnerListView.Columns[I].Width;
    else
      Break;
    end;
  end;
end;

procedure TFormOpenDialog.cxShellListView1MouseUp(Sender: TObject;
  Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
begin
  SaveColumnStatus;
end;

procedure TFormOpenDialog.cxShellTreeView1MouseUp(Sender: TObject;
  Button: TMouseButton; Shift: TShiftState; X, Y: Integer);
begin
  SaveColumnStatus;
end;

procedure TFormOpenDialog.dxShellBreadcrumbEdit1PathSelected(Sender: TObject);
begin
  SaveColumnStatus;
end;

procedure TFormOpenDialog.ESearchKeyPress(Sender: TObject; var Key: Char);
begin
  if key = Char(VK_RETURN) then
    TimerSearchTimer(TimerSearch);
end;

procedure TFormOpenDialog.ESearchPropertiesEditValueChanged(Sender: TObject);
begin
  TimerSearch.Enabled := false;
  TimerSearch.Enabled := True;
end;

procedure TFormOpenDialog.FormClose(Sender: TObject; var Action: TCloseAction);
begin
  TimerSearch.Enabled := false;
end;

procedure TFormOpenDialog.FormShow(Sender: TObject);
begin
  FWidthColumn0 := 400;
  FWidthColumn1 := 100;
  FWidthColumn2 := 100;
  FWidthColumn3 := 100;
  RestoreColumns;
end;

function TFormOpenDialog.GetInitialDir: String;
begin
  Result := cxShellListView1.Path;
end;

procedure TFormOpenDialog.SetInitialDir(const Value: String);
begin
  cxShellListView1.Path := Value;
end;

procedure TFormOpenDialog.TimerSearchTimer(Sender: TObject);
begin
  SaveColumnStatus;
  TimerSearch.Enabled               := False;
  cxShellListView1.Options.FileMask := ESearch.Text;
  RestoreColumns;
end;



procedure TFormOpenDialog.EFilterPropertiesValidate(Sender: TObject;
  var DisplayValue: Variant; var ErrorText: TCaption; var Error: Boolean);
begin
   if VarIsNull(DisplayValue) then Exit;

   if not ValidateWinPCAPFilterExpression(DisplayValue) then
   begin
      ErrorText := 'Invalid filter';
      Error     := True;
   end;    
end;

end.
