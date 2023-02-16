program PcapAnalyze;

uses
  Vcl.Forms,
  UnMain in 'UnMain.pas' {Form2},
  wpcap.Conts in '..\..\Source\wpcap.Conts.pas',
  wpcap.Protocol in '..\..\Source\wpcap.Protocol.pas',
  wpcap.StrUtils in '..\..\Source\wpcap.StrUtils.pas',
  wpcap.Types in '..\..\Source\wpcap.Types.pas',
  wpcap.Wrapper in '..\..\Source\wpcap.Wrapper.pas',
  wpcap.Offline in '..\..\Source\wpcap.Offline.pas',
  wpcap.IOUtils in '..\..\Source\wpcap.IOUtils.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TForm2, Form2);
  Application.Run;
end.
