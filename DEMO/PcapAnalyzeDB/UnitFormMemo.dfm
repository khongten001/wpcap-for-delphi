object FormMemo: TFormMemo
  Left = 0
  Top = 0
  Caption = 'FormMemo'
  ClientHeight = 511
  ClientWidth = 596
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poMainFormCenter
  OnClose = FormClose
  PixelsPerInch = 96
  TextHeight = 13
  object cxMemo1: TcxMemo
    Left = 0
    Top = 0
    Align = alClient
    Lines.Strings = (
      'cxMemo1')
    Properties.ReadOnly = True
    Properties.ScrollBars = ssBoth
    TabOrder = 0
    ExplicitLeft = 240
    ExplicitTop = 144
    ExplicitWidth = 185
    ExplicitHeight = 89
    Height = 511
    Width = 596
  end
end
