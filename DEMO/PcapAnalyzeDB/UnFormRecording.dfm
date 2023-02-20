object FormRecording: TFormRecording
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Recording module'
  ClientHeight = 459
  ClientWidth = 624
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poMainFormCenter
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object cxGroupBox1: TcxGroupBox
    Left = 0
    Top = 416
    Align = alBottom
    PanelStyle.Active = True
    TabOrder = 0
    Height = 43
    Width = 624
    object BCancel: TcxButton
      Left = 509
      Top = 4
      Width = 111
      Height = 35
      Align = alRight
      Cancel = True
      Caption = 'Cancel'
      ModalResult = 2
      TabOrder = 0
    end
    object BEndRecording: TcxButton
      Left = 398
      Top = 4
      Width = 111
      Height = 35
      Align = alRight
      Caption = 'Stort recording'
      Enabled = False
      ModalResult = 1
      TabOrder = 1
      OnClick = BEndRecordingClick
    end
    object BStartRecording: TcxButton
      Left = 287
      Top = 4
      Width = 111
      Height = 35
      Align = alRight
      Caption = 'Start recording'
      ModalResult = 2
      TabOrder = 2
      OnClick = BStartRecordingClick
    end
    object cxLabel1: TcxLabel
      Left = 4
      Top = 4
      Align = alClient
      Properties.Alignment.Vert = taVCenter
      Transparent = True
      AnchorY = 22
    end
  end
  object cxGroupBox2: TcxGroupBox
    Left = 0
    Top = 0
    Align = alTop
    PanelStyle.Active = True
    TabOrder = 1
    Height = 43
    Width = 624
  end
  object ListInterface: TcxCheckListBox
    Left = 0
    Top = 86
    Width = 624
    Height = 330
    Align = alClient
    EditValueFormat = cvfCaptions
    Items = <>
    TabOrder = 2
    ExplicitTop = 43
    ExplicitHeight = 373
  end
  object cxGroupBox3: TcxGroupBox
    Left = 0
    Top = 43
    Align = alTop
    PanelStyle.Active = True
    TabOrder = 3
    Height = 43
    Width = 624
    object cxLabel2: TcxLabel
      AlignWithMargins = True
      Left = 7
      Top = 7
      Align = alLeft
      Caption = 'Filter by WinPCAP API:'
      Properties.Alignment.Vert = taVCenter
      Transparent = True
      AnchorY = 22
    end
    object EFilter: TcxTextEdit
      AlignWithMargins = True
      Left = 127
      Top = 7
      Align = alClient
      ParentShowHint = False
      Properties.ValidationOptions = [evoShowErrorIcon, evoAllowLoseFocus]
      Properties.OnValidate = EFilterPropertiesValidate
      ShowHint = True
      TabOrder = 1
      ExplicitLeft = 134
      ExplicitHeight = 21
      Width = 490
    end
  end
end
