object FormPlayerWave: TFormPlayerWave
  Left = 0
  Top = 0
  Caption = 'Audio  player'
  ClientHeight = 411
  ClientWidth = 814
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poMainFormCenter
  OnResize = FormResize
  PixelsPerInch = 96
  TextHeight = 13
  object PaintBox1: TPaintBox
    Left = 0
    Top = 0
    Width = 814
    Height = 381
    Align = alClient
    OnPaint = PaintBox1Paint
    ExplicitLeft = 272
    ExplicitTop = 192
    ExplicitWidth = 105
    ExplicitHeight = 105
  end
  object MediaPlayer1: TMediaPlayer
    Left = 0
    Top = 381
    Width = 813
    Height = 30
    Align = alBottom
    ColoredButtons = []
    EnabledButtons = [btPlay, btPause, btStop, btNext, btPrev, btStep, btBack]
    VisibleButtons = [btPlay, btPause, btStop, btNext, btPrev, btStep, btBack]
    DoubleBuffered = True
    ParentDoubleBuffered = False
    ParentShowHint = False
    ShowHint = True
    TabOrder = 0
  end
end
