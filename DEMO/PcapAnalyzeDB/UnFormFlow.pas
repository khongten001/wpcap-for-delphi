unit UnFormFlow;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes, Vcl.Graphics,
  Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.OleCtrls, SHDocVw, dxSkinsCore,System.Win.Registry ,
  dxSkinBasic, System.ImageList, Vcl.ImgList, cxImageList, cxGraphics, dxBar,
  cxClasses, dxShellDialogs,WinApi.ActiveX;

type
  TFormFlow = class(TForm)
    wbBrowser: TWebBrowser;
    dxBarManager1: TdxBarManager;
    dxBarManager1Bar1: TdxBar;
    BSaveHTML: TdxBarButton;
    cxImageList1: TcxImageList;
    dxSaveFileDialog1: TdxSaveFileDialog;
    procedure BSaveHTMLClick(Sender: TObject);
    procedure FormCreate(Sender: TObject);
  private
    function EmbeddedWebbrowserMode(AppName: string=''; UseGPU: Integer=1): LongInt;
    { Private declarations }
  public
    { Public declarations }
    Procedure LoadHTML(const aHTML:String);
  end;

implementation

{$R *.dfm}



function Is64BitWindows: Boolean;
type TIsWow64Process = function(hProcess: THandle; var Wow64Process: BOOL): BOOL; stdcall;
var
  IsWow64: TIsWow64Process;
  Wow64Process: BOOL;
begin
  Result := False;
  IsWow64 := GetProcAddress(GetModuleHandle('kernel32'), 'IsWow64Process');
  if Assigned(IsWow64) then
  begin
    if not IsWow64(GetCurrentProcess, Wow64Process) then
      RaiseLastOSError;
    Result := Wow64Process;
  end;
end;

function TFormFlow.EmbeddedWebbrowserMode(AppName: string=''; UseGPU: Integer=1): LongInt;
const
  {32_BIT}
  REG_KEY              = 'Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION';
  REG_KEY_GPU          = 'Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_GPU_RENDERING';
  REG_KEY_TIMER        = 'Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALIGNED_TIMERS';
  REG_KEY_MITIGATION   = 'Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SCRIPTURL_MITIGATION';
  REG_KEY_LEGACYMODE   = 'Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_NINPUT_LEGACYMODE';
  REG_KEY_CHILDOPT     = 'Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_CLIPCHILDREN_OPTIMIZATION';



  {64_BIT}
  REG_KEY_64             = 'Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION';
  REG_KEY_GPU_64         = 'Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_GPU_RENDERING';
  REG_KEY_TIMER_64       = 'Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALIGNED_TIMERS';
  REG_KEY_MITIGATION_64  = 'Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_SCRIPTURL_MITIGATION';
  REG_KEY_LEGACYMODE_64  = 'Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_NINPUT_LEGACYMODE';
  REG_KEY_CHILDOPT_64    = 'Software\WOW6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_CLIPCHILDREN_OPTIMIZATION';
  REG_KEY_GPU_ENABLE_1 = 'Software\Microsoft\Internet Explorer\GPU';
  REG_KEY_GPU_ENABLE_2 = 'Software\Microsoft\Internet Explorer\Main';


var Reg     : TRegistry;
    Value   : LongInt;

  Function WriteReg(RootKey:HKEY;const Key,Name:String;iValue:LongInt):LongInt;
  begin
    Result := iValue;
    Reg:=nil;
    Try
      Reg := TRegistry.Create();
      try

       Reg.RootKey := RootKey;
        if( Reg.OpenKey(Key, True) ) then
        begin
          Reg.WriteInteger(Name,iValue);
          result :=iValue;
          Reg.CloseKey;
        end;
      except;
        ;
      end;
    Finally
      FreeAndNil(Reg);
    End;
  end;
begin
  Result  :=0;

  if AppName = '' then
    AppName := ExtractFileName(Application.ExeName);

  WriteReg(HKEY_CURRENT_USER,REG_KEY_GPU,AppName,UseGPU);
  WriteReg(HKEY_CURRENT_USER,REG_KEY_TIMER,AppName,1);
  WriteReg(HKEY_CURRENT_USER,REG_KEY_MITIGATION,AppName,1);
  WriteReg(HKEY_CURRENT_USER,REG_KEY_LEGACYMODE,AppName,0);
  WriteReg(HKEY_CURRENT_USER,REG_KEY_CHILDOPT,AppName,1);


  WriteReg(HKEY_LOCAL_MACHINE,REG_KEY_GPU,AppName,UseGPU);
  WriteReg(HKEY_LOCAL_MACHINE,REG_KEY_TIMER,AppName,1);
  WriteReg(HKEY_LOCAL_MACHINE,REG_KEY_MITIGATION,AppName,1);
  WriteReg(HKEY_LOCAL_MACHINE,REG_KEY_LEGACYMODE,AppName,0);
  WriteReg(HKEY_LOCAL_MACHINE,REG_KEY_CHILDOPT,AppName,1);
  if Is64BitWindows  then
  begin
    WriteReg(HKEY_LOCAL_MACHINE,REG_KEY_GPU_64,AppName,UseGPU);
    WriteReg(HKEY_LOCAL_MACHINE,REG_KEY_TIMER_64,AppName,1);
    WriteReg(HKEY_LOCAL_MACHINE,REG_KEY_MITIGATION_64,AppName,1);
    WriteReg(HKEY_LOCAL_MACHINE,REG_KEY_LEGACYMODE_64,AppName,0);
    WriteReg(HKEY_LOCAL_MACHINE,REG_KEY_CHILDOPT_64,AppName,1);
  end;

  Value := 11001;

  Value := WriteReg(HKEY_CURRENT_USER,REG_KEY,AppName,Value);
  WriteReg(HKEY_LOCAL_MACHINE,REG_KEY,AppName,Value);
  if Is64BitWindows then
    WriteReg(HKEY_LOCAL_MACHINE,REG_KEY_64,AppName,Value);

  if UseGPU = 1 then
  begin
    WriteReg(HKEY_CURRENT_USER,REG_KEY_GPU_ENABLE_1,'SoftwareFallback',0);
    WriteReg(HKEY_CURRENT_USER,REG_KEY_GPU_ENABLE_2,'UseSWRender',0);
  end
  else
  begin
    WriteReg(HKEY_CURRENT_USER,REG_KEY_GPU_ENABLE_1,'SoftwareFallback',1);
    WriteReg(HKEY_CURRENT_USER,REG_KEY_GPU_ENABLE_2,'UseSWRender',1)
  end;

end;


{ TForm1 }

procedure TFormFlow.LoadHTML(const aHTML: String);
var LDoc: Variant;
begin
  if NOT Assigned(wbBrowser.Document) then
    wbBrowser.Navigate('about:blank');

  LDoc := wbBrowser.Document;
  LDoc.Clear;
  LDoc.Write(aHTML);
  LDoc.Close;
end;

procedure TFormFlow.BSaveHTMLClick(Sender: TObject);
var Lps: IPersistStreamInit;
    Lfs: TFileStream;
    Lsa: IStream;
begin
  if dxSaveFileDialog1.Execute then
  begin

    Lps := wbBrowser.Document as IPersistStreamInit;
    Lfs := TFileStream.Create(dxSaveFileDialog1.FileName, fmCreate);
    try
      Lsa := TStreamAdapter.Create(Lfs, soReference) as IStream;
      Lps.Save(Lsa, True);
    finally
      Lfs.Free;
    end;
  end;

end;

procedure TFormFlow.FormCreate(Sender: TObject);
begin
  EmbeddedWebbrowserMode();
end;

end.
