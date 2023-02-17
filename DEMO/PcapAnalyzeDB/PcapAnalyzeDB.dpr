program PcapAnalyzeDB;

uses
  Vcl.Forms,
  UnMain in 'UnMain.pas' {Form2},
  wpcap.Offline.SQLite in '..\..\Source\wpcap.Offline.SQLite.pas',
  wpcap.Conts in '..\..\Source\wpcap.Conts.pas',
  wpcap.IOUtils in '..\..\Source\wpcap.IOUtils.pas',
  wpcap.Offline in '..\..\Source\wpcap.Offline.pas',
  wpcap.Protocol in '..\..\Source\wpcap.Protocol.pas',
  wpcap.StrUtils in '..\..\Source\wpcap.StrUtils.pas',
  wpcap.Types in '..\..\Source\wpcap.Types.pas',
  wpcap.Wrapper in '..\..\Source\wpcap.Wrapper.pas',
  wpcap.DB.SQLite in '..\..\Source\wpcap.DB.SQLite.pas',
  wpcap.Filter in '..\..\Source\wpcap.Filter.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TForm2, Form2);
  Application.Run;
end.
