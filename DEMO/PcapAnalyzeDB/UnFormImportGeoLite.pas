unit UnFormImportGeoLite;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants,wpcap.types,
  System.Classes, Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, cxGraphics,
  cxControls, cxLookAndFeels, wpcap.Logger, cxLookAndFeelPainters, dxSkinsCore,
  dxSkinBasic, dxCustomWizardControl, System.UiTypes, dxWizardControl,
  System.ImageList, Vcl.ImgList, cxImageList, cxContainer, cxEdit, cxLabel,
  cxTextEdit, cxMaskEdit, cxButtonEdit, cxGroupBox, dxShellDialogs,
  cxProgressBar, wpcap.GEOLite2, dxFormattedLabel;

type
  TFormImportGeoLite = class(TForm)
    dxWizardControl1: TdxWizardControl;
    wPageAsn: TdxWizardControlPage;
    wPageLocation: TdxWizardControlPage;
    cxImageList1: TcxImageList;
    cxGroupBox2: TcxGroupBox;
    EASNIpv6: TcxButtonEdit;
    cxLabel3: TcxLabel;
    cxGroupBox1: TcxGroupBox;
    EASNIpv4: TcxButtonEdit;
    cxLabel1: TcxLabel;
    dxOpenFileDialog1: TdxOpenFileDialog;
    wEndOperation: TdxWizardControlPage;
    cxGroupBox3: TcxGroupBox;
    ELocationIPv4: TcxButtonEdit;
    cxLabel2: TcxLabel;
    cxGroupBox4: TcxGroupBox;
    ELocationIPv6: TcxButtonEdit;
    cxLabel4: TcxLabel;
    cxProgressBar1: TcxProgressBar;
    LInfo: TcxLabel;
    dxFormattedLabel1: TdxFormattedLabel;
    cxGroupBox5: TcxGroupBox;
    cxButtonEdit1: TcxButtonEdit;
    cxLabel5: TcxLabel;
    procedure dxWizardControl1PageChanging(Sender: TObject;
      ANewPage: TdxWizardControlCustomPage; var AAllow: Boolean);
    procedure dxWizardControl1ButtonClick(Sender: TObject;
      AKind: TdxWizardControlButtonKind; var AHandled: Boolean);
    procedure EASNIpv4PropertiesButtonClick(Sender: TObject;
      AButtonIndex: Integer);
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure FormCloseQuery(Sender: TObject; var CanClose: Boolean);
  private
    { Private declarations }
    var FAbort          : Boolean;
    procedure DoOnLog(const aFunctionName, aDescription: String;
      aLevel: TWpcapLvlLog);
    var FDatabaseOutPut : String;
    var FWpcapGeoLite   : TWpcapGEOLITE;
    var FLogger         : TwpcapLogger;   
    Procedure DoOnProgressImport(aKink : TGeoLiteDBType;aProgress:Integer;aMax:Integer;var aAbort:Boolean);
    procedure DoOnImportCompleate(const AImportAborted: boolean);
  public
    { Public declarations }
    Property DatabaseOutPut : String       read FDatabaseOutPut write FDatabaseOutPut;
    Property Logger         : TwpcapLogger read FLogger         write FLogger;
  end;

var
  FormImportGeoLite: TFormImportGeoLite;

implementation



{$R *.dfm}

procedure TFormImportGeoLite.dxWizardControl1PageChanging(Sender: TObject;
  ANewPage: TdxWizardControlCustomPage; var AAllow: Boolean);
begin
  if ANewPage = wPageLocation then
    AAllow := FileExists(EASNIpv4.Text) or FileExists(EASNIpv6.Text)
  else if ANewPage = wEndOperation then
    AAllow := FileExists(ELocationIPv4.Text) or FileExists(ELocationIPv6.Text);
  if not AAllow then
    MessageDlg('Select one database file',mtWarning,[mbOK],0);
end;

Procedure TFormImportGeoLite.DoOnProgressImport(aKink : TGeoLiteDBType;aProgress:Integer;aMax:Integer;var aAbort:Boolean);
begin
  cxProgressBar1.Properties.Max := aMax;
  cxProgressBar1.Position       := aProgress;
  case aKink of
    gbtASNv4      : LInfo.Caption := 'Import ASN IPv4';
    gbtASNv6      : LInfo.Caption := 'Import ASN IPv6';
    gbtLocationv4 : LInfo.Caption := 'Import Location IPv4';
    gbtLocationv6 : LInfo.Caption := 'Import Location IPv6';
  end;
  aAbort := FAbort;
end;

procedure TFormImportGeoLite.dxWizardControl1ButtonClick(Sender: TObject;
  AKind: TdxWizardControlButtonKind; var AHandled: Boolean);

begin
  case AKind of
    wcbkCancel:
      begin
         FAbort := True;
         Close;
      end;
    wcbkFinish: 
      begin
        FWpcapGeoLite.OnProgressImport  := DoOnProgressImport; 
        FWpcapGeoLite.OnImportCompleate := DoOnImportCompleate;
        FWpcapGeoLite.LoadGeoLiteCSVAsync(EASNIpv4.Text,EASNIpv6.Text,ELocationIPv4.Text,ELocationIPv6.Text,DatabaseOutPut);
        dxWizardControl1.Buttons.Finish.Enabled := False;
      end;
  end;
end;

Procedure TFormImportGeoLite.DoOnImportCompleate(const AImportAborted: boolean);
begin
  if not AImportAborted then
    MessageDlg('Import compleate',mtInformation,[mbOK],0);
  dxWizardControl1.Buttons.Finish.Enabled := True;
  Close;
end;

procedure TFormImportGeoLite.EASNIpv4PropertiesButtonClick(Sender: TObject;
  AButtonIndex: Integer);
begin
  if dxOpenFileDialog1.Execute then
    TcxButtonEdit(Sender).Text := dxOpenFileDialog1.FileName;
end;

procedure TFormImportGeoLite.FormCreate(Sender: TObject);
begin
  FWpcapGeoLite       := TWpcapGEOLITE.Create;
  FWpcapGeoLite.OnLog := DoOnLog;
  FLogger             := TWpcapLogger.Create(nil);
  FLogger.PathLog     := AnsiString(Format('%sLog\',[ExtractFilePath(Application.ExeName)]));
  FLogger.MaxDayLog   := 7;
  FLogger.Active      := True;
  FLogger.Debug       := False;    
end;

procedure TFormImportGeoLite.DoOnLog(const aFunctionName,aDescription: String; aLevel: TWpcapLvlLog);
begin 
  FLogger.LOG__WriteiLog(aFunctionName,aDescription,aLevel);
end;

procedure TFormImportGeoLite.FormDestroy(Sender: TObject);
begin
  FreeAndNil(FLogger);
  FreeAndNil(FWpcapGeoLite);
end;

procedure TFormImportGeoLite.FormCloseQuery(Sender: TObject;
  var CanClose: Boolean);
begin
  CanClose := dxWizardControl1.Buttons.Finish.Enabled;  
end;

end.
