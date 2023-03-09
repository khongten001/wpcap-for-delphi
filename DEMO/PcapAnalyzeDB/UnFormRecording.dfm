object FormRecording: TFormRecording
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Recording module'
  ClientHeight = 691
  ClientWidth = 1091
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poMainFormCenter
  OnCloseQuery = FormCloseQuery
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object dxNavBar1: TdxNavBar
    Left = 1051
    Top = 0
    Width = 40
    Height = 691
    Align = alRight
    ActiveGroupIndex = 0
    TabOrder = 0
    ViewReal = 15
    OptionsBehavior.NavigationPane.Collapsible = True
    OptionsBehavior.NavigationPane.Collapsed = True
    OptionsView.Common.ShowGroupCaptions = False
    OptionsView.NavigationPane.ShowActiveGroupCaptionWhenCollapsed = True
    OptionsView.NavigationPane.ShowOverflowPanel = False
    OriginalWidth = 259
    object dxNavBar1Group1: TdxNavBarGroup
      Caption = 'Options'
      SelectedLinkIndex = -1
      TopVisibleLinkIndex = 0
      OptionsGroupControl.AllowControlResizing = True
      OptionsGroupControl.ShowControl = True
      OptionsGroupControl.UseControl = True
      Links = <>
    end
    object dxNavBar1Group1Control: TdxNavBarGroupControl
      Left = 0
      Top = 0
      Width = 40
      Height = 691
      Caption = 'dxNavBar1Group1Control'
      TabOrder = 0
      UseStyle = True
      GroupIndex = 0
      OriginalHeight = 41
      object cxLabel4: TcxLabel
        AlignWithMargins = True
        Left = 3
        Top = 3
        Align = alTop
        Caption = 'Time out(ms)'
        Properties.Alignment.Vert = taVCenter
        Transparent = True
        AnchorY = 12
      end
      object sTimeOutMs: TcxSpinEdit
        AlignWithMargins = True
        Left = 3
        Top = 26
        Align = alTop
        Properties.Alignment.Horz = taRightJustify
        Properties.Increment = 250.000000000000000000
        Properties.LargeIncrement = 1000.000000000000000000
        Properties.MinValue = 500.000000000000000000
        Properties.SpinButtons.Position = sbpHorzLeftRight
        Properties.SpinButtons.ShowFastButtons = True
        TabOrder = 1
        Value = 1000
        Width = 34
      end
      object cxLabel5: TcxLabel
        AlignWithMargins = True
        Left = 3
        Top = 53
        Align = alTop
        Caption = 'Max size packet(bytes)'
        Properties.Alignment.Vert = taVCenter
        Transparent = True
        AnchorY = 62
      end
      object sMaxSizePacket: TcxSpinEdit
        AlignWithMargins = True
        Left = 3
        Top = 76
        Align = alTop
        Properties.Alignment.Horz = taRightJustify
        Properties.Increment = 500.000000000000000000
        Properties.LargeIncrement = 1000.000000000000000000
        Properties.MaxValue = 65535.000000000000000000
        Properties.MinValue = 500.000000000000000000
        Properties.SpinButtons.Position = sbpHorzLeftRight
        Properties.SpinButtons.ShowFastButtons = True
        TabOrder = 3
        Value = 65535
        Width = 34
      end
      object ChkEnabledStopRecording: TcxCheckBox
        Left = 0
        Top = 100
        Align = alTop
        Caption = 'Stop recordin at:'
        Properties.OnEditValueChanged = ChkEnabledStopRecordingPropertiesEditValueChanged
        Style.TransparentBorder = False
        TabOrder = 4
        Transparent = True
      end
      object tStopRecordingTime: TcxTimeEdit
        AlignWithMargins = True
        Left = 3
        Top = 123
        Align = alTop
        Properties.Alignment.Horz = taRightJustify
        Properties.Circular = True
        Properties.Increment = 10.000000000000000000
        Properties.LargeIncrement = 60.000000000000000000
        Properties.SpinButtons.Position = sbpHorzLeftRight
        Properties.SpinButtons.ShowFastButtons = True
        TabOrder = 5
        Width = 34
      end
    end
  end
  object cxGroupBox4: TcxGroupBox
    Left = 0
    Top = 0
    Align = alClient
    Caption = 'cxGroupBox4'
    TabOrder = 1
    Height = 691
    Width = 1051
    object cxGroupBox1: TcxGroupBox
      Left = 4
      Top = 632
      Align = alBottom
      PanelStyle.Active = True
      TabOrder = 0
      Height = 43
      Width = 1043
      object BCancel: TcxButton
        Left = 928
        Top = 4
        Width = 111
        Height = 35
        Align = alRight
        Cancel = True
        Caption = 'Cancel'
        ModalResult = 2
        OptionsImage.ImageIndex = 2
        OptionsImage.Images = cxImageList1
        TabOrder = 0
      end
      object BEndRecording: TcxButton
        Left = 817
        Top = 4
        Width = 111
        Height = 35
        Align = alRight
        Caption = 'Stort recording'
        Enabled = False
        ModalResult = 1
        OptionsImage.ImageIndex = 0
        OptionsImage.Images = cxImageList1
        TabOrder = 1
        OnClick = BEndRecordingClick
      end
      object BStartRecording: TcxButton
        Left = 706
        Top = 4
        Width = 111
        Height = 35
        Align = alRight
        Caption = 'Start recording'
        OptionsImage.ImageIndex = 3
        OptionsImage.Images = cxImageList1
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
      Left = 4
      Top = 16
      Align = alTop
      PanelStyle.Active = True
      TabOrder = 1
      Height = 43
      Width = 1043
      object EPathDB: TcxButtonEdit
        AlignWithMargins = True
        Left = 86
        Top = 7
        Align = alClient
        Properties.Buttons = <
          item
            Default = True
            ImageIndex = 1
            Hint = 'Select a file'
            Kind = bkGlyph
          end>
        Properties.Images = cxImageList1
        Properties.OnButtonClick = EPathDBPropertiesButtonClick
        TabOrder = 0
        ExplicitWidth = 783
        Width = 793
      end
      object cxLabel3: TcxLabel
        AlignWithMargins = True
        Left = 7
        Top = 7
        Align = alLeft
        Caption = 'Dabase name:'
        Properties.Alignment.Vert = taVCenter
        Transparent = True
        AnchorY = 22
      end
      object TSfileDumb: TdxToggleSwitch
        AlignWithMargins = True
        Left = 885
        Top = 7
        Align = alRight
        Caption = 'Save dump file'
        Checked = False
        Style.TransparentBorder = False
        TabOrder = 2
        Transparent = True
        ExplicitLeft = 875
      end
    end
    object cxGroupBox3: TcxGroupBox
      Left = 4
      Top = 59
      Align = alTop
      PanelStyle.Active = True
      TabOrder = 2
      Height = 43
      Width = 1043
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
        Width = 909
      end
    end
    object ListInterface: TcxTreeList
      Left = 4
      Top = 102
      Width = 1043
      Height = 530
      Align = alClient
      Bands = <
        item
        end>
      FindPanel.DisplayMode = fpdmAlways
      FindPanel.Layout = fplCompact
      Navigator.Buttons.CustomButtons = <>
      OptionsBehavior.CellHints = True
      OptionsData.CancelOnExit = False
      OptionsData.Editing = False
      OptionsData.Deleting = False
      OptionsView.CellAutoHeight = True
      OptionsView.CellEndEllipsis = True
      OptionsView.ColumnAutoWidth = True
      OptionsView.CheckGroups = True
      OptionsView.ShowRoot = False
      ScrollbarAnnotations.CustomAnnotations = <>
      TabOrder = 3
      Data = {
        00000500DF0000000F00000044617461436F6E74726F6C6C6572310500000012
        000000546378537472696E6756616C7565547970651200000054637853747269
        6E6756616C75655479706512000000546378537472696E6756616C7565547970
        6513000000546378426F6F6C65616E56616C7565547970651200000054637853
        7472696E6756616C75655479706502000000445855464D5401445855464D5401
        020000000000000008000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF0100
        000008000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF1A0C1002000000}
      object ListInterfaceColumnNAME: TcxTreeListColumn
        Caption.Text = 'Simple name'
        Width = 233
        Position.ColIndex = 0
        Position.RowIndex = 0
        Position.BandIndex = 0
        Summary.FooterSummaryItems = <>
        Summary.GroupFooterSummaryItems = <>
      end
      object ListInterfaceColumGUID: TcxTreeListColumn
        Caption.Text = 'GUID'
        Width = 283
        Position.ColIndex = 1
        Position.RowIndex = 0
        Position.BandIndex = 0
        Summary.FooterSummaryItems = <>
        Summary.GroupFooterSummaryItems = <>
      end
      object ListInterfaceCOMMENT: TcxTreeListColumn
        Caption.Text = 'Comment'
        Width = 197
        Position.ColIndex = 2
        Position.RowIndex = 0
        Position.BandIndex = 0
        Summary.FooterSummaryItems = <>
        Summary.GroupFooterSummaryItems = <>
      end
      object ListInterfaceColumIP: TcxTreeListColumn
        BestFitMaxWidth = 40
        Caption.Text = 'Promisc'
        DataBinding.ValueType = 'Boolean'
        Width = 43
        Position.ColIndex = 4
        Position.RowIndex = 0
        Position.BandIndex = 0
        Summary.FooterSummaryItems = <>
        Summary.GroupFooterSummaryItems = <>
      end
      object ListInterfaceColumPROMISC: TcxTreeListColumn
        Caption.Text = 'IP'
        Width = 110
        Position.ColIndex = 3
        Position.RowIndex = 0
        Position.BandIndex = 0
        Summary.FooterSummaryItems = <>
        Summary.GroupFooterSummaryItems = <>
      end
    end
  end
  object SaveDialog1: TSaveDialog
    DefaultExt = '.db'
    Filter = 'SQLite database (.db)| *.db'
    Left = 488
    Top = 208
  end
  object cxImageList1: TcxImageList
    SourceDPI = 96
    FormatVersion = 1
    Left = 584
    Top = 296
    Bitmap = {
      494C010104000800040010001000FFFFFFFF2110FFFFFFFFFFFFFFFF424D3600
      0000000000003600000028000000400000002000000001002000000000000020
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      00000000021A07073A88131392D51B1BC9FB1B1BCAFB141494D708083C8A0000
      021B000000000000000000000000000000000000000000000000BD680EEFD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFD77610FFC16A0FF200000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000303
      18581919BCF21B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1919
      BDF303031A5C0000000000000000000000000000000000000000D77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFD77610FFD77610FF0000000000000000000000000002031E0B638FBF14B1
      FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF14B1FFFF073F5C9900000000000000000000000000000000000000000000
      005B000000E30000002A00000000000000000000000000000000000000270000
      00E10000005F0000000000000000000000000000000000000000030318571B1B
      CEFD1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BCFFE03031A5C00000000000000000000000000000000D77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFD77610FFD77610FF00000000000000000000000004253676010E144814B1
      FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF14B1FFFF14AAF5FA0002031E000000000000000000000000000000000000
      00DC000000FF000000E80000002A000000000000000000000027000000E50000
      00FF000000E100000000000000000000000000000000000001181818BAF11B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1919BDF30000021B000000000000000000000000D77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFD77610FFD77610FF0000000000000000000000000B5F87BA000101140D75
      A9D014B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF14B1FFFF14B1FFFF0637508F000000000000000000000000000000000000
      0024000000E3000000FF000000E80000002A00000027000000E5000000FF0000
      00E50000002700000000000000000000000000000000070738851B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF08083C8A000000000000000000000000D77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFD77610FFD77610FF0000000000000000000000000B638FBF031C28660215
      1E5914B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF14B1FFFF14B1FFFF12A1E7F3000001120000000000000000000000000000
      000000000024000000E3000000FF000000E8000000E5000000FF000000E50000
      0027000000000000000000000000000000000000000012128DD21B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF131394D7000000000000000000000000D77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFD77610FFD77610FF0000000000000000000000000B638FBF0A577DB30000
      000E0F86C1DE14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF14B1FFFF14B1FFFF14B1FFFF04293B7B0000000000000000000000000000
      00000000000000000024000000E3000000FF000000FF000000E5000000270000
      000000000000000000000000000000000000000000001919C2F61B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1A1ACAFB000000000000000000000000D77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFD77610FFD77610FF0000000000000000000000000B638FBF0B638FBF0214
      1D57031E2B6A14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF14B1FFFF14B1FFFF14B1FFFF108CCAE30000000000000000000000000000
      00000000000000000027000000E5000000FF000000FF000000E80000002A0000
      000000000000000000000000000000000000000000001919C1F51B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1A1AC9FB000000000000000000000000D77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFD77610FFD77610FF0000000000000000000000000B638FBF0B638FBF094F
      71AA000001120000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000027000000E5000000FF000000E5000000E3000000FF000000E80000
      002A000000000000000000000000000000000000000012128AD01B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF131392D5000000000000000000000000D77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFD77610FFD77610FF0000000000000000000000000B638FBF0B638FBF0B63
      8FBF0B638FBF0B638FBF0B638FBF0B638FBF0B638FBF0B638FBF0B638FBF0B63
      8FBF0B638FBF0000000000000000000000000000000000000000000000000000
      0027000000E5000000FF000000E50000002700000024000000E3000000FF0000
      00E80000002A00000000000000000000000000000000070736831B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF07073A88000000000000000000000000D77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFD77610FFD77610FF0000000000000000000000000B638FBF0B638FBF0B63
      8FBF0B638FBF0B638FBF0B638FBF0B638FBF0B638FBF0B638FBF0B638FBF0B63
      8FBF0A5980B50000000000000000000000000000000000000000000000000000
      00DD000000FF000000E500000027000000000000000000000024000000E30000
      00FF000000E300000000000000000000000000000000000001171818B8F01B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1919BCF20000021A000000000000000000000000D77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFD77610FFD77610FF0000000000000000000000000B638FBF0B638FBF0B63
      8FBF0B638FBF0B638FBF00000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0056000000DD0000002700000000000000000000000000000000000000240000
      00DC0000005B0000000000000000000000000000000000000000020216531B1B
      CDFD1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BCEFD0303185800000000000000000000000000000000B9650EEDD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFD77610FFBD680EEF0000000000000000000000000A577DB30B638FBF0B63
      8FBF0B638FBF0A5980B500000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000202
      16531818B8F01B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1818
      BAF1030318570000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000001170707368312128AD01919C1F51919C2F612128CD1070737840000
      0118000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000424D3E000000000000003E000000
      2800000040000000200000000100010000000000000100000000000000000000
      000000000000000000000000FFFFFF0000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000}
    DesignInfo = 19399240
    ImageInfo = <
      item
        ImageClass = 'TdxSmartImage'
        Image.Data = {
          3C3F786D6C2076657273696F6E3D22312E302220656E636F64696E673D225554
          462D38223F3E0D0A3C7376672076657273696F6E3D22312E31222069643D224C
          617965725F312220786D6C6E733D22687474703A2F2F7777772E77332E6F7267
          2F323030302F7376672220786D6C6E733A786C696E6B3D22687474703A2F2F77
          77772E77332E6F72672F313939392F786C696E6B2220783D223070782220793D
          22307078222076696577426F783D2230203020333220333222207374796C653D
          22656E61626C652D6261636B67726F756E643A6E657720302030203332203332
          3B2220786D6C3A73706163653D227072657365727665223E262331333B262331
          303B3C7374796C6520747970653D22746578742F637373223E2E426C75657B66
          696C6C3A233131373744373B7D3C2F7374796C653E0D0A3C7061746820636C61
          73733D22426C75652220643D224D32372C34483543342E352C342C342C342E35
          2C342C3576323263302C302E352C302E352C312C312C3168323263302E352C30
          2C312D302E352C312D3156354332382C342E352C32372E352C342C32372C347A
          222F3E0D0A3C2F7376673E0D0A}
      end
      item
        ImageClass = 'TdxSmartImage'
        Image.Data = {
          3C3F786D6C2076657273696F6E3D22312E302220656E636F64696E673D225554
          462D38223F3E0D0A3C7376672076657273696F6E3D22312E31222069643D224F
          70656E2220786D6C6E733D22687474703A2F2F7777772E77332E6F72672F3230
          30302F7376672220786D6C6E733A786C696E6B3D22687474703A2F2F7777772E
          77332E6F72672F313939392F786C696E6B2220783D223070782220793D223070
          78222076696577426F783D2230203020333220333222207374796C653D22656E
          61626C652D6261636B67726F756E643A6E6577203020302033322033323B2220
          786D6C3A73706163653D227072657365727665223E262331333B262331303B3C
          7374796C6520747970653D22746578742F6373732220786D6C3A73706163653D
          227072657365727665223E2E59656C6C6F777B66696C6C3A234646423131353B
          7D262331333B262331303B2623393B2E7374307B6F7061636974793A302E3735
          3B7D3C2F7374796C653E0D0A3C6720636C6173733D22737430223E0D0A09093C
          7061746820636C6173733D2259656C6C6F772220643D224D322E322C32352E32
          6C352E352D313263302E332D302E372C312D312E322C312E382D312E32483236
          563963302D302E362D302E342D312D312D31483132563563302D302E362D302E
          342D312D312D31483343322E342C342C322C342E342C322C3576323020202623
          393B2623393B63302C302E322C302C302E332C302E312C302E3443322E312C32
          352E332C322E322C32352E332C322E322C32352E327A222F3E0D0A093C2F673E
          0D0A3C7061746820636C6173733D2259656C6C6F772220643D224D33312E332C
          313448392E364C342C32366832312E3863302E352C302C312E312D302E332C31
          2E332D302E374C33322C31342E374333322E312C31342E332C33312E382C3134
          2C33312E332C31347A222F3E0D0A3C2F7376673E0D0A}
      end
      item
        ImageClass = 'TdxSmartImage'
        Image.Data = {
          3C3F786D6C2076657273696F6E3D22312E302220656E636F64696E673D225554
          462D38223F3E0D0A3C7376672076657273696F6E3D22312E31222069643D224C
          617965725F312220786D6C6E733D22687474703A2F2F7777772E77332E6F7267
          2F323030302F7376672220786D6C6E733A786C696E6B3D22687474703A2F2F77
          77772E77332E6F72672F313939392F786C696E6B2220783D223070782220793D
          22307078222076696577426F783D223020302033322033322220656E61626C65
          2D6261636B67726F756E643D226E6577203020302033322033322220786D6C3A
          73706163653D227072657365727665223E262331333B262331303B3C70617468
          20643D224D31392E312C31366C362E362D362E3663302E342D302E342C302E34
          2D312C302D312E344C32342C362E33632D302E342D302E342D312D302E342D31
          2E342C304C31362C31322E394C392E342C362E3343392C352E392C382E342C35
          2E392C382C362E334C362E332C3820202623393B632D302E342C302E342D302E
          342C312C302C312E346C362E362C362E366C2D362E362C362E36632D302E342C
          302E342D302E342C312C302C312E344C382C32352E3763302E342C302E342C31
          2C302E342C312E342C306C362E362D362E366C362E362C362E3663302E342C30
          2E342C312C302E342C312E342C3020202623393B6C312E372D312E3763302E34
          2D302E342C302E342D312C302D312E344C31392E312C31367A222F3E0D0A3C2F
          7376673E0D0A}
      end
      item
        ImageClass = 'TdxSmartImage'
        Image.Data = {
          3C3F786D6C2076657273696F6E3D22312E302220656E636F64696E673D225554
          462D38223F3E0D0A3C7376672076657273696F6E3D22312E31222069643D224C
          617965725F312220786D6C6E733D22687474703A2F2F7777772E77332E6F7267
          2F323030302F7376672220786D6C6E733A786C696E6B3D22687474703A2F2F77
          77772E77332E6F72672F313939392F786C696E6B2220783D223070782220793D
          22307078222076696577426F783D2230203020333220333222207374796C653D
          22656E61626C652D6261636B67726F756E643A6E657720302030203332203332
          3B2220786D6C3A73706163653D227072657365727665223E262331333B262331
          303B3C7374796C6520747970653D22746578742F637373223E2E5265647B6669
          6C6C3A234431314331433B7D3C2F7374796C653E0D0A3C7061746820636C6173
          733D225265642220643D224D31362C3243382E332C322C322C382E332C322C31
          3673362E332C31342C31342C31347331342D362E332C31342D31345332332E37
          2C322C31362C327A222F3E0D0A3C2F7376673E0D0A}
      end>
  end
end
