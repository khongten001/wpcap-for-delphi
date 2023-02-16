program PcapAnalyze;

uses
  Vcl.Forms,
  UnMain in 'UnMain.pas' {Form2},
  wpcap.Conts in '..\..\Source\wpcap.Conts.pas',
  wpcap.protocol in '..\..\Source\wpcap.protocol.pas',
  wpcap.StrUtils in '..\..\Source\wpcap.StrUtils.pas',
  wpcap.Types in '..\..\Source\wpcap.Types.pas',
  wpcap.wrapper in '..\..\Source\wpcap.wrapper.pas';

{$R *.res}

begin
  Application.Initialize;
  Application.MainFormOnTaskbar := True;
  Application.CreateForm(TForm2, Form2);
  Application.Run;
end.
