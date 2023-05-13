object FormMain: TFormMain
  Left = 0
  Top = 0
  Caption = 'PCAP Analisys'
  ClientHeight = 788
  ClientWidth = 1460
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  WindowState = wsMaximized
  OnClose = FormClose
  OnCreate = FormCreate
  OnDestroy = FormDestroy
  PixelsPerInch = 96
  TextHeight = 13
  object GridPcap: TcxGrid
    Left = 0
    Top = 45
    Width = 838
    Height = 706
    Align = alClient
    TabOrder = 0
    LockedStateImageOptions.Effect = lsieDark
    LockedStateImageOptions.ShowText = True
    object GridPcapDBTableView1: TcxGridDBTableView
      PopupMenu = PopupGrid
      Navigator.Buttons.CustomButtons = <>
      FilterBox.CriteriaDisplayStyle = fcdsTokens
      FindPanel.DisplayMode = fpdmAlways
      FindPanel.Layout = fplCompact
      FindPanel.Location = fplGroupByBox
      ScrollbarAnnotations.CustomAnnotations = <>
      OnCellClick = GridPcapDBTableView1CellClick
      OnCustomDrawCell = GridPcapDBTableView1CustomDrawCell
      OnFocusedRecordChanged = GridPcapDBTableView1FocusedRecordChanged
      DataController.DataSource = DsGrid
      DataController.Summary.DefaultGroupSummaryItems = <
        item
          Kind = skCount
          Column = GridPcapDBTableView1NPACKET
        end
        item
          Kind = skSum
          OnGetText = GridPcapTableView1TcxGridDataControllerTcxDataSummaryFooterSummaryItems0GetText
          Column = GridPcapDBTableView1PACKET_LEN
        end>
      DataController.Summary.FooterSummaryItems = <
        item
          Kind = skSum
          OnGetText = GridPcapTableView1TcxGridDataControllerTcxDataSummaryFooterSummaryItems0GetText
          Column = GridPcapDBTableView1PACKET_LEN
        end
        item
          Kind = skCount
          Column = GridPcapDBTableView1NPACKET
        end>
      DataController.Summary.SummaryGroups = <>
      Filtering.ColumnPopupMode = fpmExcel
      OptionsBehavior.CellHints = True
      OptionsCustomize.ColumnsQuickCustomization = True
      OptionsData.CancelOnExit = False
      OptionsData.Deleting = False
      OptionsData.DeletingConfirmation = False
      OptionsData.Inserting = False
      OptionsView.CellEndEllipsis = True
      OptionsView.ShowEditButtons = gsebAlways
      OptionsView.DataRowHeight = 20
      OptionsView.Footer = True
      OptionsView.GridLines = glHorizontal
      OptionsView.HeaderEndEllipsis = True
      OptionsView.HeaderHeight = 30
      OptionsView.Indicator = True
      OptionsView.ShowColumnFilterButtons = sfbAlways
      object GridPcapDBTableView1NPACKET: TcxGridDBColumn
        Caption = 'Count'
        DataBinding.FieldName = 'NPACKET'
        Options.Editing = False
        Width = 82
      end
      object GridPcapDBTableView1PACKET_DATE: TcxGridDBColumn
        Caption = 'Date'
        DataBinding.FieldName = 'PACKET_DATE'
        Options.Editing = False
        Width = 120
      end
      object GridPcapDBTableView1FLOW_ID: TcxGridDBColumn
        Caption = 'ID. Flow'
        DataBinding.FieldName = 'FLOW_ID'
        Options.Editing = False
      end
      object GridPcapDBTableView1IP_SRC: TcxGridDBColumn
        Caption = 'Source'
        DataBinding.FieldName = 'IP_SRC'
        Options.Editing = False
        Width = 150
      end
      object GridPcapDBTableView1PORT_SRC: TcxGridDBColumn
        Caption = 'Port src'
        DataBinding.FieldName = 'PORT_SRC'
        Options.Editing = False
      end
      object GridPcapDBTableView1IP_DST: TcxGridDBColumn
        Caption = 'Dest'
        DataBinding.FieldName = 'IP_DST'
        Options.Editing = False
        Width = 150
      end
      object GridPcapDBTableView1PORT_DST: TcxGridDBColumn
        Caption = 'Port dst'
        DataBinding.FieldName = 'PORT_DST'
        Options.Editing = False
        Width = 70
      end
      object GridPcapDBTableView1PROTOCOL: TcxGridDBColumn
        Caption = 'Protocol'
        DataBinding.FieldName = 'PROTOCOL'
        Options.Editing = False
        Width = 77
      end
      object GridPcapDBTableView1PACKET_LEN: TcxGridDBColumn
        Caption = 'Len'
        DataBinding.FieldName = 'PACKET_LEN'
        Options.Editing = False
        Width = 73
      end
      object GridPcapDBTableView1ENRICHMENT_PRESENT: TcxGridDBColumn
        Caption = 'Enrichment present'
        DataBinding.FieldName = 'ENRICHMENT_PRESENT'
        PropertiesClassName = 'TcxCheckBoxProperties'
        Properties.ValueChecked = '1'
        Properties.ValueUnchecked = '0'
        Options.Editing = False
      end
      object GridPcapDBTableView1IS_MALFORMED: TcxGridDBColumn
        Caption = 'Malformed'
        DataBinding.FieldName = 'IS_MALFORMED'
        PropertiesClassName = 'TcxCheckBoxProperties'
        Properties.ValueChecked = '1'
        Properties.ValueUnchecked = '0'
        Options.Editing = False
      end
      object GridPcapDBTableView1IS_RETRASMISSION: TcxGridDBColumn
        Caption = 'Retrasmission'
        DataBinding.FieldName = 'IS_RETRASMISSION'
        PropertiesClassName = 'TcxCheckBoxProperties'
        Properties.ValueChecked = '1'
        Properties.ValueUnchecked = '0'
        Options.Editing = False
      end
      object GridPcapDBTableView1PACKET_INFO: TcxGridDBColumn
        Caption = 'Info'
        DataBinding.FieldName = 'PACKET_INFO'
        Options.Editing = False
        Width = 200
      end
      object GridPcapDBTableView1ETH_TYPE: TcxGridDBColumn
        DataBinding.FieldName = 'ETH_TYPE'
        Visible = False
        Options.Editing = False
        Width = 109
      end
      object GridPcapDBTableView1ETH_ACRONYM: TcxGridDBColumn
        Caption = 'Eth type'
        DataBinding.FieldName = 'ETH_ACRONYM'
        Options.Editing = False
      end
      object GridPcapDBTableView1MAC_SRC: TcxGridDBColumn
        Caption = 'Mac src'
        DataBinding.FieldName = 'MAC_SRC'
        Options.Editing = False
        Width = 150
      end
      object GridPcapDBTableView1MAC_DST: TcxGridDBColumn
        Caption = 'Mac dst'
        DataBinding.FieldName = 'MAC_DST'
        Options.Editing = False
        Width = 150
      end
      object GridPcapDBTableView1IPPROTO: TcxGridDBColumn
        DataBinding.FieldName = 'IPPROTO'
        Visible = False
        Options.Editing = False
      end
      object GridPcapDBTableView1PROTO_DETECT: TcxGridDBColumn
        DataBinding.FieldName = 'PROTO_DETECT'
        Visible = False
        Options.Editing = False
        VisibleForCustomization = False
      end
      object GridPcapDBTableView1IANA_PROTO: TcxGridDBColumn
        Caption = 'IANA_Protocol'
        DataBinding.FieldName = 'IANA_PROTO'
        Options.Editing = False
      end
      object GridPcapDBTableView1NOTE: TcxGridDBColumn
        Caption = 'Note'
        DataBinding.FieldName = 'NOTE_PACKET'
        PropertiesClassName = 'TcxMemoProperties'
        Options.ShowEditButtons = isebAlways
        Width = 277
      end
      object GridPcapDBTableView1IPPROTO_STR: TcxGridDBColumn
        Caption = 'IP protocol'
        DataBinding.FieldName = 'IPPROTO_STR'
        Options.Editing = False
      end
      object GridPcapDBTableView1ASN: TcxGridDBColumn
        Caption = 'Src ASN'
        DataBinding.FieldName = 'SRC_ASN'
        Options.Editing = False
      end
      object GridPcapDBTableView1ORGANIZZATION: TcxGridDBColumn
        Caption = 'Organizzation'
        DataBinding.FieldName = 'SRC_ORGANIZZATION'
        Options.Editing = False
      end
      object GridPcapDBTableView1DST_ASN: TcxGridDBColumn
        Caption = 'Dst ASN'
        DataBinding.FieldName = 'DST_ASN'
        Options.Editing = False
      end
      object GridPcapDBTableView1DstORGANIZZATION: TcxGridDBColumn
        Caption = 'Dst organizzation'
        DataBinding.FieldName = 'DST_ORGANIZZATION'
        Options.Editing = False
      end
      object GridPcapDBTableView1SRC_LATITUDE: TcxGridDBColumn
        DataBinding.FieldName = 'SRC_LATITUDE'
        Visible = False
        Options.Editing = False
      end
      object GridPcapDBTableView1SRC_LONGITUDE: TcxGridDBColumn
        DataBinding.FieldName = 'SRC_LONGITUDE'
        Visible = False
        Options.Editing = False
      end
      object GridPcapDBTableView1DST_LATITUDE: TcxGridDBColumn
        DataBinding.FieldName = 'DST_LATITUDE'
        Visible = False
        Options.Editing = False
      end
      object GridPcapDBTableView1DST_LONGITUDE: TcxGridDBColumn
        DataBinding.FieldName = 'DST_LONGITUDE'
        Visible = False
        Options.Editing = False
      end
      object GridPcapDBTableView1PACKET_RAW_TEXT: TcxGridDBColumn
        Caption = 'Raw data'
        DataBinding.FieldName = 'PACKET_RAW_TEXT'
        Visible = False
        Options.Editing = False
        VisibleForCustomization = False
        Width = 150
      end
      object GridPcapDBTableView1XML_PACKET_DETAIL: TcxGridDBColumn
        Caption = 'Packet detail'
        DataBinding.FieldName = 'XML_PACKET_DETAIL'
        Visible = False
        Options.Editing = False
        VisibleForCustomization = False
        Width = 150
      end
    end
    object GridPcapLevel1: TcxGridLevel
      GridView = GridPcapDBTableView1
    end
  end
  object cxSplitter1: TcxSplitter
    Left = 838
    Top = 45
    Width = 10
    Height = 706
    AlignSplitter = salRight
    Control = PHexMemo
  end
  object PHexMemo: TcxGroupBox
    Left = 848
    Top = 45
    Align = alRight
    PanelStyle.Active = True
    TabOrder = 2
    Height = 706
    Width = 612
    object MemoHex: TcxMemo
      Left = 4
      Top = 432
      Align = alBottom
      Lines.Strings = (
        '')
      ParentShowHint = False
      Properties.ReadOnly = True
      Properties.ScrollBars = ssBoth
      ShowHint = True
      TabOrder = 0
      Height = 250
      Width = 604
    end
    object dxBarDockControl1: TdxBarDockControl
      Left = 4
      Top = 4
      Width = 604
      Height = 22
      Align = dalTop
      BarManager = dxBarManager1
    end
    object cxSplitter2: TcxSplitter
      Left = 4
      Top = 422
      Width = 604
      Height = 10
      AlignSplitter = salBottom
      Control = MemoHex
    end
    object ListPacketDetail: TcxTreeList
      Left = 4
      Top = 26
      Width = 604
      Height = 396
      Align = alClient
      Bands = <
        item
        end>
      FindPanel.DisplayMode = fpdmAlways
      FindPanel.Layout = fplCompact
      Navigator.Buttons.CustomButtons = <>
      OptionsBehavior.CellHints = True
      OptionsBehavior.CopyCaptionsToClipboard = False
      OptionsData.CancelOnExit = False
      OptionsData.Editing = False
      OptionsData.Deleting = False
      OptionsView.CellEndEllipsis = True
      OptionsView.ColumnAutoWidth = True
      OptionsView.Headers = False
      OptionsView.Indicator = True
      PopupMenu = dxBarPopupMenu1
      ScrollbarAnnotations.CustomAnnotations = <>
      TabOrder = 3
      OnClick = ListPacketDetailClick
      OnFocusedNodeChanged = ListPacketDetailFocusedNodeChanged
      object ListPacketDetailDescription: TcxTreeListColumn
        DataBinding.ValueType = 'Variant'
        Width = 230
        Position.ColIndex = 0
        Position.RowIndex = 0
        Position.BandIndex = 0
        Summary.FooterSummaryItems = <>
        Summary.GroupFooterSummaryItems = <>
      end
      object ListPacketDetailValue: TcxTreeListColumn
        DataBinding.ValueType = 'Variant'
        Width = 118
        Position.ColIndex = 1
        Position.RowIndex = 0
        Position.BandIndex = 0
        Summary.FooterSummaryItems = <>
        Summary.GroupFooterSummaryItems = <>
      end
      object ListPacketDetailRawValue: TcxTreeListColumn
        DataBinding.ValueType = 'Variant'
        Width = 30
        Position.ColIndex = 2
        Position.RowIndex = 0
        Position.BandIndex = 0
        Summary.FooterSummaryItems = <>
        Summary.GroupFooterSummaryItems = <>
        OnGetDisplayText = ListPacketDetailRawValueGetDisplayText
      end
      object ListPacketDetailHex: TcxTreeListColumn
        Width = 100
        Position.ColIndex = 3
        Position.RowIndex = 0
        Position.BandIndex = 0
        Summary.FooterSummaryItems = <>
        Summary.GroupFooterSummaryItems = <>
      end
      object ListPacketDetailLabel: TcxTreeListColumn
        Visible = False
        Width = 100
        Position.ColIndex = 4
        Position.RowIndex = 0
        Position.BandIndex = 0
        Summary.FooterSummaryItems = <>
        Summary.GroupFooterSummaryItems = <>
      end
      object ListPacketDetailSize: TcxTreeListColumn
        Visible = False
        DataBinding.ValueType = 'Integer'
        Width = 100
        Position.ColIndex = 5
        Position.RowIndex = 0
        Position.BandIndex = 0
        Summary.FooterSummaryItems = <>
        Summary.GroupFooterSummaryItems = <>
      end
      object ListPacketDetailEnrichment: TcxTreeListColumn
        PropertiesClassName = 'TcxImageComboBoxProperties'
        Properties.Images = cxImageList1
        Properties.Items = <
          item
            Value = 0
          end
          item
            Description = 'GeoIP'
            ImageIndex = 9
            Value = 1
          end
          item
            Description = 'MCC'
            ImageIndex = 8
            Value = 2
          end
          item
            Description = 'MNC'
            Value = 3
          end
          item
            Description = 'IMSI'
            Value = 4
          end
          item
            Description = 'Content'
            ImageIndex = 0
            Value = 5
          end>
        Properties.ShowDescriptions = False
        DataBinding.ValueType = 'Integer'
        Width = 20
        Position.ColIndex = 6
        Position.RowIndex = 0
        Position.BandIndex = 0
        Summary.FooterSummaryItems = <>
        Summary.GroupFooterSummaryItems = <>
      end
    end
    object dxStatusBar1: TdxStatusBar
      Left = 4
      Top = 682
      Width = 604
      Height = 20
      Panels = <>
      PaintStyle = stpsUseLookAndFeel
      SimplePanelStyle.Active = True
      SizeGrip = False
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -11
      Font.Name = 'Tahoma'
      Font.Style = []
      ShowHint = True
      ParentShowHint = False
    end
  end
  object pProgressImport: TcxGroupBox
    Left = 0
    Top = 751
    Align = alBottom
    PanelStyle.Active = True
    TabOrder = 7
    Visible = False
    Height = 37
    Width = 1460
    object cxProgressBar1: TcxProgressBar
      AlignWithMargins = True
      Left = 7
      Top = 7
      Align = alClient
      TabOrder = 0
      Width = 1371
    end
    object cxButton1: TcxButton
      Left = 1381
      Top = 4
      Width = 75
      Height = 29
      Align = alRight
      Caption = 'Cancel'
      TabOrder = 1
      OnClick = cxButton1Click
    end
  end
  object DsGrid: TDataSource
    Left = 1056
    Top = 488
  end
  object dxBarManager1: TdxBarManager
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -12
    Font.Name = 'Segoe UI'
    Font.Style = []
    Categories.Strings = (
      'Default')
    Categories.ItemsVisibles = (
      2)
    Categories.Visibles = (
      True)
    ImageOptions.Images = cxImageList1
    PopupMenuLinks = <>
    Style = bmsUseLookAndFeel
    UseSystemFont = True
    Left = 240
    Top = 320
    PixelsPerInch = 96
    DockControlHeights = (
      0
      0
      45
      0)
    object dxBarManager1Bar1: TdxBar
      AllowClose = False
      AllowCustomizing = False
      AllowQuickCustomizing = False
      Caption = 'MainMenu'
      CaptionButtons = <>
      DockedDockingStyle = dsTop
      DockedLeft = 0
      DockedTop = 23
      DockingStyle = dsTop
      FloatLeft = 1229
      FloatTop = 2
      FloatClientWidth = 0
      FloatClientHeight = 0
      ItemLinks = <
        item
          Visible = True
          ItemName = 'BStartRecording'
        end
        item
          BeginGroup = True
          Visible = True
          ItemName = 'BLoadPCAP'
        end
        item
          Visible = True
          ItemName = 'BLoadSQLLiteDatabase'
        end
        item
          BeginGroup = True
          Visible = True
          ItemName = 'BSavePCAP'
        end
        item
          Visible = True
          ItemName = 'BSaevGrid'
        end
        item
          BeginGroup = True
          Visible = True
          ItemName = 'BMap'
        end
        item
          Visible = True
          ItemName = 'BSubWhoise'
        end
        item
          Visible = True
          ItemName = 'BFlow'
        end>
      NotDocking = [dsNone, dsLeft, dsTop, dsRight, dsBottom]
      OneOnRow = True
      Row = 1
      UseOwnFont = False
      UseRecentItems = False
      UseRestSpace = True
      Visible = True
      WholeRow = True
    end
    object dxBarManager1Bar2: TdxBar
      AllowClose = False
      AllowCustomizing = False
      AllowQuickCustomizing = False
      AllowReset = False
      Caption = 'MenuHex'
      CaptionButtons = <>
      DockControl = dxBarDockControl1
      DockedDockControl = dxBarDockControl1
      DockedLeft = 0
      DockedTop = 0
      FloatLeft = 1128
      FloatTop = 2
      FloatClientWidth = 0
      FloatClientHeight = 0
      ItemLinks = <
        item
          Visible = True
          ItemName = 'BCopyTreeList'
        end
        item
          BeginGroup = True
          Visible = True
          ItemName = 'BSaveListPacket'
        end
        item
          BeginGroup = True
          Visible = True
          ItemName = 'BSavePacket'
        end>
      NotDocking = [dsNone, dsLeft, dsTop, dsRight, dsBottom]
      OneOnRow = True
      Row = 0
      UseOwnFont = False
      Visible = True
      WholeRow = True
    end
    object dxBarManager1Bar3: TdxBar
      AllowClose = False
      AllowCustomizing = False
      AllowQuickCustomizing = False
      AllowReset = False
      Caption = 'MenuOldSylte'
      CaptionButtons = <>
      DockedDockingStyle = dsTop
      DockedLeft = 0
      DockedTop = 0
      DockingStyle = dsTop
      FloatLeft = 1488
      FloatTop = 2
      FloatClientWidth = 0
      FloatClientHeight = 0
      ItemLinks = <
        item
          Visible = True
          ItemName = 'BMenuFile'
        end
        item
          Visible = True
          ItemName = 'BQuickFilter'
        end
        item
          Visible = True
          ItemName = 'BUtility'
        end
        item
          Visible = True
          ItemName = 'BSubTools'
        end
        item
          Visible = True
          ItemName = 'BSettings'
        end>
      NotDocking = [dsNone, dsLeft, dsTop, dsRight, dsBottom]
      OneOnRow = True
      Row = 0
      UseOwnFont = False
      UseRestSpace = True
      Visible = True
      WholeRow = True
    end
    object BSavePCAP: TdxBarButton
      Caption = 'Save PCAP'
      Category = 0
      Enabled = False
      Hint = 'Save PCAP'
      Visible = ivAlways
      ImageIndex = 1
      ShortCut = 16467
      OnClick = BSavePCAPClick
    end
    object BLoadPCAP: TdxBarButton
      Caption = 'Load PCAP'
      Category = 0
      Hint = 'Load PCAP'
      Visible = ivAlways
      ImageIndex = 0
      ShortCut = 16463
      OnClick = BLoadPCAPClick
    end
    object BStartRecording: TdxBarButton
      Caption = 'Capture'
      Category = 0
      Hint = 'Capture'
      Visible = ivAlways
      ImageIndex = 2
      ShortCut = 16462
      OnClick = BStartRecordingClick
    end
    object BSavePacket: TdxBarButton
      Caption = 'Save packet'
      Category = 0
      Enabled = False
      Hint = 'Save packet'
      Visible = ivAlways
      ImageIndex = 1
      PaintStyle = psCaptionGlyph
      OnClick = BSavePacketClick
    end
    object BSaveListPacket: TdxBarButton
      Caption = 'Save list'
      Category = 0
      Enabled = False
      Hint = 'Save list'
      Visible = ivAlways
      ImageIndex = 3
      PaintStyle = psCaptionGlyph
      OnClick = BSaveListPacketClick
    end
    object BSaevGrid: TdxBarButton
      Caption = 'Save grid'
      Category = 0
      Enabled = False
      Hint = 'Save grid'
      Visible = ivAlways
      ImageIndex = 3
      ShortCut = 16467
      OnClick = BSaevGridClick
    end
    object BCopyGrid: TdxBarButton
      Caption = 'Copy'
      Category = 0
      Hint = 'Copy'
      Visible = ivAlways
      ImageIndex = 4
      OnClick = BCopyGridClick
    end
    object dxBarButton1: TdxBarButton
      Caption = 'Load GeoIP'
      Category = 0
      Hint = 'Load GeoIP'
      Visible = ivAlways
      ImageIndex = 12
      OnClick = dxBarButton1Click
    end
    object TActiveGEOIP: TcxBarEditItem
      Caption = 'Active GeoIP'
      Category = 0
      Hint = 'Active GeoIP'
      Visible = ivAlways
      ShowCaption = True
      Width = 0
      PropertiesClassName = 'TdxToggleSwitchProperties'
      Properties.DisplayGrayed = 'False'
      Properties.ImmediatePost = True
      Properties.ShowEndEllipsis = True
      InternalEditValue = False
    end
    object BSubTools: TdxBarSubItem
      Caption = 'Imports'
      Category = 0
      Visible = ivAlways
      ImageIndex = 15
      ItemLinks = <
        item
          Visible = True
          ItemName = 'dxBarSeparator1'
        end
        item
          Visible = True
          ItemName = 'dxBarButton1'
        end>
    end
    object dxBarSeparator1: TdxBarSeparator
      Caption = 'GeoIP'
      Category = 0
      Hint = 'GeoIP'
      Visible = ivAlways
    end
    object BMap: TdxBarButton
      Caption = 'Map'
      Category = 0
      Enabled = False
      Hint = 'Map'
      Visible = ivAlways
      ImageIndex = 5
      OnClick = BMapClick
    end
    object BFlow: TdxBarButton
      Caption = 'Flow stream'
      Category = 0
      Enabled = False
      Hint = 'Flow stream'
      Visible = ivAlways
      ImageIndex = 7
      OnClick = BFlowClick
    end
    object BRTPCall: TdxBarButton
      Caption = 'Try decode RTP audio'
      Category = 0
      Hint = 'Try decode RTP audio'
      Visible = ivAlways
      OnClick = BRTPCallClick
    end
    object BQuickFilter: TdxBarSubItem
      Caption = 'Quick filters'
      Category = 0
      Visible = ivAlways
      ImageIndex = 6
      ItemLinks = <
        item
          Visible = True
          ItemName = 'BFilterCellValue'
        end
        item
          Visible = True
          ItemName = 'BFilterFlowSelected'
        end
        item
          Visible = True
          ItemName = 'BFilterByLabelForm'
        end>
    end
    object BFilterCellValue: TdxBarButton
      Caption = 'For value of select column'
      Category = 0
      Enabled = False
      Hint = 'For value of select column'
      Visible = ivAlways
      ShortCut = 32838
      OnClick = BFilterCellValueClick
    end
    object BFilterFlowSelected: TdxBarButton
      Caption = 'Flow selected'
      Category = 0
      Enabled = False
      Hint = 'Flow selected'
      Visible = ivAlways
      OnClick = BFilterFlowSelectedClick
    end
    object BCopyTreeList: TdxBarButton
      Caption = 'Copy'
      Category = 0
      Enabled = False
      Hint = 'Copy'
      Visible = ivAlways
      ImageIndex = 4
      ShortCut = 16451
      OnClick = BCopyTreeListClick
    end
    object BFilterByLabel: TdxBarButton
      Caption = 'Filter element with this label'
      Category = 0
      Enabled = False
      Hint = 'Filter element with this label'
      Visible = ivAlways
      ImageIndex = 6
      OnClick = BFilterByLabelClick
    end
    object BLoadSQLLiteDatabase: TdxBarButton
      Caption = 'Load database SQLLite'
      Category = 0
      Hint = 'Load database SQLLite'
      Visible = ivAlways
      ImageIndex = 10
      OnClick = BLoadSQLLiteDatabaseClick
    end
    object BFilterByLabelForm: TdxBarButton
      Caption = 'Label list filter'
      Category = 0
      Enabled = False
      Hint = 'Label list filter'
      Visible = ivAlways
      OnClick = BFilterByLabelFormClick
    end
    object BSubWhoise: TdxBarSubItem
      Caption = 'Whois'
      Category = 0
      Visible = ivAlways
      ImageIndex = 13
      ShowCaption = False
      ItemLinks = <
        item
          Visible = True
          ItemName = 'BWhoiseServer'
        end
        item
          Visible = True
          ItemName = 'BWhoiseClient'
        end>
    end
    object BWhoiseServer: TdxBarButton
      Caption = 'Server'
      Category = 0
      Enabled = False
      Hint = 'Server'
      Visible = ivAlways
      OnClick = BWhoiseServerClick
    end
    object BWhoiseClient: TdxBarButton
      Caption = 'Client'
      Category = 0
      Enabled = False
      Hint = 'Client'
      Visible = ivAlways
      OnClick = BWhoiseClientClick
    end
    object TActiveVerobse: TcxBarEditItem
      Caption = 'Verbose log'
      Category = 0
      Hint = 'Verbose log'
      Visible = ivAlways
      ShowCaption = True
      Width = 0
      PropertiesClassName = 'TdxToggleSwitchProperties'
      Properties.ImmediatePost = True
      Properties.ShowEndEllipsis = True
      Properties.ValueGrayed = 'False'
      InternalEditValue = 'False'
    end
    object BSettings: TdxBarSubItem
      Caption = 'Settings'
      Category = 0
      Visible = ivAlways
      ImageIndex = 14
      ItemLinks = <
        item
          ViewLayout = ivlGlyphControlCaption
          Visible = True
          ItemName = 'TActiveGEOIP'
        end
        item
          ViewLayout = ivlGlyphControlCaption
          Visible = True
          ItemName = 'TActiveVerobse'
        end>
    end
    object BMenuFile: TdxBarSubItem
      Caption = 'File'
      Category = 0
      Visible = ivAlways
      ImageIndex = 16
      ItemLinks = <
        item
          Visible = True
          ItemName = 'BStartRecording'
        end
        item
          BeginGroup = True
          Visible = True
          ItemName = 'BLoadPCAP'
        end
        item
          Visible = True
          ItemName = 'BLoadSQLLiteDatabase'
        end
        item
          BeginGroup = True
          Visible = True
          ItemName = 'BSaevGrid'
        end
        item
          Visible = True
          ItemName = 'BSavePCAP'
        end
        item
          BeginGroup = True
          Visible = True
          ItemName = 'dxBarButton2'
        end>
    end
    object dxBarButton2: TdxBarButton
      Caption = 'Exit'
      Category = 0
      Hint = 'Exit'
      Visible = ivAlways
      OnClick = dxBarButton2Click
    end
    object BUtility: TdxBarSubItem
      Caption = 'Utility'
      Category = 0
      Visible = ivAlways
      ImageIndex = 17
      ItemLinks = <
        item
          Visible = True
          ItemName = 'BMap'
        end
        item
          Visible = True
          ItemName = 'BSubWhoise'
        end
        item
          Visible = True
          ItemName = 'BFlow'
        end>
    end
  end
  object cxImageList1: TcxImageList
    SourceDPI = 96
    FormatVersion = 1
    Left = 320
    Top = 376
    Bitmap = {
      494C010112001800040010001000FFFFFFFF2110FFFFFFFFFFFFFFFF424D3600
      0000000000003600000028000000400000005000000001002000000000000050
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000C723F08BA884B0BCB0000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000636363EF717171FF717171FF7171
      71FF717171FF717171FF717171FF717171FF717171FF717171FF717171FF4040
      40C1010000177B4309C1D77610FF764009BD0000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000129BE0EF14B1FFFF14B1FFFF14B1
      FFFF129FE5F2000000000000000000000000717171FF00000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000C7B4309C1D77610FF7B4309C10000000C0000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF717171FF717171FF0000000014B1FFFF14B1FFFF14B1FFFF14B1
      FFFF14B1FFFF000000000000000000000000717171FF00000000000000000000
      00000000000000000000000000000000000747270593C16A0FF2C56C0FF49D56
      0CDAD77610FF7B4309C10000000C000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF0000000000000000000000001298DCED14B1FFFF14B1FFFF14B1
      FFFF129BE0EF000000000000000000000000717171FF00000000000000007171
      71FF717171FF717171FF0000000044250590D77610FFD77610FFD57510FED776
      10FFA45A0DDF0000000C00000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF0000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000717171FF00000000000000000000
      0000000000000000000000000000BA670EEEC36C0FF30D07014104020024D575
      10FEC76D0FF50000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF0000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000717171FF00000000000000007171
      71FF717171FF717171FF00000000A85C0DE20C07003E000000000D070141D776
      10FFC16A0FF20000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF000000000000000000000000129BE0EF14B1FFFF14B1FFFF14B1
      FFFF129FE5F2000000000000000000000000717171FF00000000000000000000
      000000000000000000000000000001000016000000000C07003EC36C0FF3D776
      10FF472705930000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF717171FF717171FF0000000014B1FFFF14B1FFFF14B1FFFF14B1
      FFFF14B1FFFF000000000000000000000000717171FF00000000000000007171
      71FF717171FF717171FF717171FF717171FF01000016A85C0DE2BA660EED4425
      0590010000160000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF000000000000000000000000129ADEEE14B1FFFF14B1FFFF14B1
      FFFF129EE3F1000000000000000000000000717171FF00000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000505050D60000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF0000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000717171FF000000000000000014B1
      FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF000000000000
      0000717171FF0000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000717171FF00000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF0000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000129FE5F214B1
      FFFF14B1FFFF14B1FFFF13A3EBF5000000000000000000000000000000000000
      000000000000000000000000000000000000717171FF00000000000000007171
      71FF717171FF717171FF717171FF717171FF717171FF717171FF000000000000
      0000717171FF0000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000000000000000000014B1FFFF14B1
      FFFF14B1FFFF14B1FFFF14B1FFFF000000000000000000000000000000000000
      000000000000000000000000000000000000717171FF00000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF0000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000129ADEEE14B1
      FFFF14B1FFFF14B1FFFF129EE3F1000000000000000000000000000000000000
      000000000000000000000000000000000000717171FF00000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF0000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000626262ED717171FF717171FF7171
      71FF717171FF717171FF717171FF717171FF717171FF717171FF717171FF7171
      71FF636363EF0000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000371E04820000
      00000000000000000000000000000000000000000000371E0482371E04820000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000001B0E025BA45A0DDF0000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000D77610FF371E
      048200000000000000000000000000000000371E048292500BD2D77610FF371E
      048200000000000000000000000000000000636363EF717171FF717171FF7171
      71FF717171FF717171FF717171FF717171FF505050D70A0A0A4F0000000A0000
      0000000000001B0E025BCD7010F91B0E025B0000000000000000000000000000
      0000000000000000000001000014D77610FFD77610FF01000017000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      00000201001A3D21048896530BD5CF7210FBD07210FB98530BD73E22048A0201
      001B000000000000000000000000000000000000000000000000D77610FFD776
      10FF371E04820000000000000000371E048292500BD201000015D77610FFD776
      10FF371E0482000000000000000000000000717171FF00000000000000000000
      0000000000000000000000000000000000000000000747270593C16A0FF2C16A
      0FF2633608ADCD7010F91B0E025B00000000000000000000000000000000140B
      014F03020022000000000E070142D77610FFD77610FF0D070140000000000603
      002E180D0256000000000000000000000000000000000000000000000000190E
      0258C16A0FF2D77610FFD77610FFD77610FFD77610FFD77610FFD77610FFC36B
      0FF31B0F025C0000000000000000000000000000000000000000D77610FFD776
      10FFD77610FF371E0482371E048292500BD20100001500000000D77610FFD776
      10FFD77610FF371E04820000000000000000717171FF00000000000000000000
      00000000000000000000000000000000000044250590653808AF010000150100
      0013623507AC653708AF00000000000000000000000000000000150C0151D174
      10FCC0690FF1301A037984480AC8D77610FFD77610FF8D4E0BCF3D220488C96E
      0FF7D37410FD150C015100000000000000000000000000000000180D0257D474
      10FDD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFD57510FE1B0F025C00000000000000000000000000000000D77610FFD776
      10FFD77610FFD77610FF92500BD2010000150000000000000000D77610FFD776
      10FFD77610FFD77610FF0000000000000000717171FF0000000000000000D776
      10FF000000001C1C1C7F1C1C1C7F00000008BA670EEE01010018000000000000
      000001000013C16A0FF2000000000000000000000000000000000503002AC76D
      0FF5D77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFBD680EEF0301001F00000000000000000000000001010018C0690FF1D776
      10FFD77610FFD77610FFD77610FF331C037D331C037DD77610FFD77610FFD776
      10FFD77610FFC36C0FF30201001B000000000000000000000000D77610FFD776
      10FFD77610FFD77610FF010000150000000000000000000000000000000C2414
      0269C96E0FF7D77610FF0000000000000000717171FF00000000000000000000
      000000000000000000000000000000000000B9650EED0201001A000000000000
      000001000015C16A0FF20000000000000000000000000000000000000000381F
      0483D77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FF2F1A0378000000000000000000000000000000003A200485D77610FFD776
      10FFD77610FFD77610FF331C037D0000000000000000331C037DD77610FFD776
      10FFD77610FFD77610FF3E22048A000000000000000000000000D77610FFD776
      10FFD77610FFD77610FF0000000000000000021119501195D6EA1198DAEC0213
      1B5424140269D77610FF0000000000000000717171FF0000000000000000D776
      10FF000000001C1C1C7F1C1C1C7F020202294124048D6A3A08B30201001A0201
      0019663808B047270593000000000000000000000000010000170D07003F884B
      0BCBD77610FFD77610FF653808AF0100001501000013623507ACD77610FFD776
      10FF874A0BCA100901470201001A000000000000000092500BD2D77610FFD776
      10FFD77610FF331C037D00000000000000000000000000000000331C037DD776
      10FFD77610FFD77610FF98530BD7000000000000000000000000D77610FFD776
      10FFD77610FFD77610FF00000000000000001190CFE614B1FFFF14B1FFFF1198
      DAEC0000000CD77610FF0000000000000000717171FF00000000000000000000
      000000000000000000000000000000000000000000064124048DB9650EEDBA66
      0EED4425059000000007000000000000000000000000D77610FFD77610FFD776
      10FFD77610FFD77610FF01010018000000000000000001000013D77610FFD776
      10FFD77610FFD77610FFD77610FF0000000000000000C76D10F6D77610FFD776
      10FFD77610FFD77610FFD77610FF0000000000000000D77610FFD77610FFD776
      10FFD77610FFD77610FFCF7210FB000000000000000000000000D77610FFD776
      10FFD77610FFD77610FF0000000000000000108FCDE514B1FFFF14B1FFFF1195
      D6EA0000000DD77610FF0000000000000000717171FF0000000000000000D776
      10FF000000001C1C1C7F1C1C1C7F1C1C1C7F1414146C0303032B000000000000
      00000D0D0D5700000000000000000000000000000000D77610FFD77610FFD776
      10FFD77610FFD77610FF0201001A000000000000000001000015D77610FFD776
      10FFD77610FFD77610FFD77610FF0000000000000000C76D0FF5D77610FFD776
      10FFD77610FFD77610FFD77610FF0000000000000000D77610FFD77610FFD776
      10FFD77610FFD77610FFCF7210FB000000000000000000000000D77610FFD776
      10FF633608AD0603002D0000000000000000010F164C108FCDE51190CFE60211
      19502615026CD77610FF0000000000000000717171FF00000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF00000000000000000000000000000000010000140E0701428A4C
      0BCDD77610FFD77610FF6A3A08B30201001A02010019663808B0D77610FFD776
      10FF8A4C0BCD0B06003A0100001200000000000000008F4E0BD0D77610FFD776
      10FFD77610FFD77610FFD77610FF0000000000000000D77610FFD77610FFD776
      10FFD77610FFD77610FF96530BD5000000000000000000000000331C037D6336
      08AD00030024145D01C5229802FC155F01C80003002500000000000000032A17
      0372CD7010F9D77610FF0000000000000000717171FF0000000000000000D776
      10FF000000001C1C1C7F1C1C1C7F1C1C1C7F1C1C1C7F1C1C1C7F000000000000
      0000717171FF000000000000000000000000000000000000000000000000361E
      0480D77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FF3E22048900000000000000000000000000000000381F0483D77610FFD776
      10FFD77610FFD77610FFD77610FF0000000000000000D77610FFD77610FFD776
      10FFD77610FFD77610FF3C210488000000000000000000000000000000000000
      000B145A01C2229C02FF229C02FF229C02FF155F01C800000000000000002F1A
      0378D77610FFD77610FF0000000000000000717171FF00000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF000000000000000000000000000000000000000004020026C36C
      0FF3D77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFCB7010F80704003100000000000000000000000001000017BE690FF0D776
      10FFD77610FFD77610FFD77610FF0000000000000000D77610FFD77610FFD776
      10FFD77610FFC16A0FF20201001A000000000000000000000000000000000000
      0000209202F7229C02FF229C02FF229C02FF229802FC00000000000000000000
      00002F1A0378D77610FF0000000000000000717171FF0000000000000000D776
      10FF000000001C1C1C7F1C1C1C7F1C1C1C7F1C1C1C7F1C1C1C7F000000000000
      0000717171FF0000000000000000000000000000000000000000180D0257D474
      10FDC76D0FF5381F048385490AC9D77610FFD77610FF83480AC72A170372BA65
      0EEDD17410FC160C015300000000000000000000000000000000160C0153D374
      10FDD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD776
      10FFD47410FD190E025800000000000000000000000000000000000000000000
      0000135701C0229C02FF229C02FF229C02FF145D01C500000000000000000000
      0000000000002F1A03780000000000000000717171FF00000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF000000000000000000000000000000000000000000000000180D
      025705020028000000000A060039D77610FFD77610FF10090146000000000201
      001C130A014C000000000000000000000000000000000000000000000000160C
      0153BE690FF0D77610FFD77610FFD77610FFD77610FFD77610FFD77610FFC069
      0FF1180D02570000000000000000000000000000000000000000000000000000
      000000020020135701C0209202F7145A01C20002002300000000000000000000
      000000000000000000000000000000000000717171FF00000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000717171FF0000000000000000000000000000000000000000000000000000
      0000000000000000000000000011D77610FFD77610FF02010019000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000001000017381F04838F4E0BD0C76D0FF5C76E0FF690500BD1391F04840101
      0018000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000626262ED717171FF717171FF7171
      71FF717171FF717171FF717171FF717171FF717171FF717171FF717171FF7171
      71FF636363EF0000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000015000000002A2A
      2A9C2D2D2DA10000000000000014000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000004041E620404226700000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000229C02FF229C02FF000000000000000000000011656565F1353535AE6262
      62EE646464F0333333AC676767F3000000140000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000052B1919C1F51A1AC3F70000062F000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000000000000000000000000000A16C
      31EFB77B37FFA46F32F200000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000229C02FF229C02FF000000000000000000000000303030A7717171FF7171
      71FF717171FF717171FF333333AC000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000612128BD01B1BD1FF1B1BD1FF131390D4000000080000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000000000000000000000000000B77B
      37FF00000000B77B37FF0000000000000000000000000000000000000009031F
      2C6B0A5E87BA1192D3E814AEFBFD14AFFDFE1198DAEC00000000229C02FF229C
      02FF229C02FF229C02FF229C02FF229C02FF2D2D2DA0636363EF717171FF0505
      053804040432717171FF646464F02D2D2DA10000000000000010000000100000
      00100000001000000010000000100000000A0000000000000000000000000000
      000000000000070737831B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF08083B890000
      0000000000000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000909094AB27A
      3BFFB77B37FFA16C30EF000000000000000000000000000000000C6B99C614B1
      FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF00000000229C02FF229C
      02FF229C02FF229C02FF229C02FF229C02FF2929299B626262ED717171FF0606
      063D05050538717171FF636363EE2A2A2A9C00000007D77610FFD77610FFD776
      10FFD77610FFD77610FFD77610FFC86E0FF60000000000000000000000000000
      00000000052A1A1AC9FA1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BCAFB0000
      062E000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000000000000909094A656464EF0808
      084600000000000000000000000000000000000000000000000013A5EDF6063A
      5694010C12450001021700000002000000010000011300000000000000000000
      0000229C02FF229C02FF000000000000000000000000313131A8717171FF7171
      71FF717171FF717171FF353535AE000000046B3B08B4D77610FFD77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FF0000000000000000000000000000
      00000E0E6EB91B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF0F0F
      74BE000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000909094A656464EF080808460000
      0000000000000000000000000000000000000000000000000000010B1041031F
      2C6B0A5E87BA1192D3E814AEFBFD14AEFBFD1194D6EA0B638FBF032231700000
      0000229C02FF229C02FF000000000000000000000011646464F0313131A86262
      62ED636363EF303030A7656565F100000015864A0ACAD77610FFD77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FF0000000000000000000000000101
      0C3E1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF01010E430000000000000000000000000000000000000000000000000000
      00000000000000000000000000000909094A656464EF08080846000000000000
      00000000000000000000000000000000000000000000000000000C6B99C614B1
      FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF0000
      0000000000000000000000000000000000000000000000000011000000002929
      299B2D2D2DA0000000000000001124140269D57610FED77610FFD77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FF0000000000000000000000000B0B
      5BA91B1BD1FF1B1BD1FF0C0C63AF00000115000001130C0C5FAC1B1BD1FF1B1B
      D1FF0C0C61AE0000000000000000000000000000000000000000000000000000
      000000000000000000000909094A656464EF0808084600000000000000000000
      000000000000000000000000000000000000000000000000000013A5EDF6063A
      5694010C124500010217000000020000000200010116010C11430639529113A3
      EBF5000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000B8650EECD77610FFD77610FFD77610FFD776
      10FFD77610FFD77610FFD77610FFBB670EEE0000000000000000000000001818
      B5ED1B1BD1FF1B1BD1FF000001180000000000000000000001131B1BD1FF1B1B
      D1FF1919BDF30000000000000000000000000000000000000000000000000000
      0000000000000909094A656464EF080808460000000000000000000000000000
      0000000000000000000000000000000000000000000000000000010B1041031F
      2C6B0A5E87BA1192D3E814AEFBFD14AEFBFD1194D4E90B608ABC03202E6D010A
      0E3D000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000001919
      BDF31B1BD1FF1B1BD1FF0000021A0000000000000000000001151B1BD1FF1B1B
      D1FF1A1AC5F80000000000000000000000000000000000000000000000000000
      00000909094A656464EF08080846000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000C6B99C614B1
      FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF0D71
      A3CC000000000000000000000000000000000000000000000000C16A0FF2D776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFC36C0FF30000
      0000000000000000000000000000000000000000000000000000000000000F0F
      73BE1B1BD1FF1B1BD1FF0D0D67B30000021A000001190D0D63B01B1BD1FF1B1B
      D1FF0F0F7AC30000000000000000000000000000000000000000000000000909
      094A656464EF0808084600000000000000000000000000000000000000000000
      000000000000000000000000000000000000000000000000000014B1FFFF14B1
      FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF000000000000000000000000000000000000000000000000D77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FF0000
      0000000000000000000000000000000000000000000000000000000000000202
      124B1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF0202145100000000000000000000000000000000A16C31EFB77B37FFB47B
      3AFF080808460000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000000000000000000014B1FFFF14B1
      FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF000000000000000000000000000000000000000000000000D77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FF0000
      0000000000000000000000000000000000000000000000000000000000000000
      0000070737831B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF0808
      3B890000000000000000000000000000000000000000B77B37FF00000000B77B
      37FF000000000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000C6795C314B1
      FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF0C6D
      9DC8000000000000000000000000000000000000000000000000D77610FFD776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FF0000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000202124B0F0F74BE1919BDF31919BDF30F0F75BF0202134E0000
      000000000000000000000000000000000000000000009E6A30EDB77B37FFA16C
      30EF000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000000000000000000000000007031C
      28660A5980B5108CCAE313A7F1F813A7F1F8108DCBE40A5982B6031D2A680000
      0008000000000000000000000000000000000000000000000000BB670EEED776
      10FFD77610FFD77610FFD77610FFD77610FFD77610FFD77610FFBD680EEF0000
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
      0000000000000000000000000000000000000000000000000000371E04820000
      00000000000000000000000000000000000000000000371E0482371E04820000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000636363EF7171
      71FF717171FF717171FF717171FF717171FF717171FF717171FF666666F20000
      0000000000000000000000000000000000000000000000000000D77610FF371E
      048200000000000000000000000000000000371E048292500BD2D77610FF371E
      0482000000000000000000000000000000000000000000000000000000000000
      00000000000000000000000000001D1D1D820000000000000000000000000000
      0000000000000000000000000000000000000000000000000000666666F27171
      71FF717171FF717171FF717171FF717171FF717171FF717171FF717171FF7171
      71FF717171FF686868F500000000000000000000000000000000717171FF0000
      0000000000000000000000000000000000000000000000000000717171FF0000
      0000000000000000000000000000000000000000000000000000D77610FFD776
      10FF371E04820000000000000000371E048292500BD201000015D77610FFD776
      10FF371E04820000000000000000000000000000000000000000000000000000
      0000000000000000000000000000717171FF1D1D1D8200000000000000000000
      0000000000000000000000000000000000000000000000000000717171FF0000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000717171FF00000000000000000000000000000000717171FF0000
      0000000000000000000000000000000000000000000000000000717171FF0000
      0000000000000000000000000000000000000000000000000000D77610FFD776
      10FFD77610FF371E0482371E048292500BD20100001500000000D77610FFD776
      10FFD77610FF371E048200000000000000000000000000000000000000000000
      0000000000000000000000000000717171FF717171FF00000000000000000000
      0000000000000000000000000000000000000000000000000000717171FF0000
      0000000000003F3F3FBF3F3F3FBF3F3F3FBF3F3F3FBF3F3F3FBF3F3F3FBF0000
      000000000000717171FF00000000000000000000000000000000717171FF0000
      0000000000000000000000000000000000000000000000000000717171FF7171
      71FF717171FF666666F200000000000000000000000000000000D77610FFD776
      10FFD77610FFD77610FF92500BD2010000150000000000000000D77610FFD776
      10FFD77610FFD77610FF00000000000000000000000000000000000000000000
      0000000000000000000000000000717171FF717171FF00000000000000000000
      0000000000000000000000000000000000000000000000000000717171FF0000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000717171FF00000000000000000000000000000000717171FF0000
      0000000000000000000000000000000000000000000000000000717171FF0000
      000000000000717171FF00000000000000000000000000000000D77610FFD776
      10FFD77610FFD77610FF01000015000000000000000000000000D77610FFD776
      10FFD77610FFD77610FF00000000000000000000000000000000000000000000
      0000000000000000000000000000717171FF717171FF00000000000000000000
      0000000000000000000000000000000000000000000000000000717171FF0000
      0000000000003F3F3FBF3F3F3FBF3F3F3FBF3F3F3FBF3F3F3FBF3F3F3FBF0000
      000000000000717171FF00000000000000000000000000000000717171FF0000
      0000000000000000000000000000000000000000000000000000717171FF0000
      000000000000717171FF00000000000000000000000000000000D77610FFD776
      10FFD77610FFD77610FF00000000000000000000000000000000D77610FFD776
      10FFD77610FFD77610FF00000000000000000000000000000000000000000000
      0000000000000000000000000000717171FF717171FF00000000000000000000
      0000000000000000000000000000000000000000000000000000717171FF0000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000717171FF00000000000000000000000000000000717171FF0000
      0000000000000000000000000000000000000000000000000000717171FF0000
      000000000000717171FF00000000000000000000000000000000D77610FFD776
      10FFD77610FFD77610FF00000000000000000000000000000000D77610FFD776
      10FFD77610FFD77610FF00000000000000000000000000000000000000000000
      0000000000000000000000000000717171FF717171FF00000000000000000000
      0000000000000000000000000000000000000000000000000000717171FF0000
      000014B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF00000000717171FF00000000000000000000000000000000717171FF0000
      0000000000000000000000000000636363EF717171FF717171FF555555DE0000
      000000000000717171FF00000000000000000000000000000000D77610FFD776
      10FFD77610FFD37410FD000000000505256C0505297100000000D27410FCD776
      10FFD77610FFD77610FF00000000000000000000000000000000000000000000
      000000000000000000001D1D1D82717171FF717171FF1D1D1D82000000000000
      0000000000000000000000000000000000000000000000000000717171FF0000
      000014B1FFFF00000000000000000000000000000000000000000000000014B1
      FFFF00000000717171FF00000000000000000000000000000000717171FF0000
      0000000000000000000000000000717171FF717171FF555555DE0101011F0000
      000000000000717171FF00000000000000000000000000000000D77610FFD776
      10FFD77610FF3B20048601010B3B1A1AC9FA1B1BCAFB01010C3F391F0484D776
      10FFD77610FFD77610FF00000000000000000000000000000000000000000000
      0000000000001D1D1D82717171FF717171FF717171FF717171FF1D1D1D820000
      0000000000000000000000000000000000000000000000000000717171FF0000
      000014B1FFFF00000000000000000000000000000000000000000000000014B1
      FFFF00000000717171FF00000000000000000000000000000000717171FF0000
      0000000000000000000000000000717171FF555555DE0101011F000000000000
      000000000000717171FF000000000000000000000000000000002F1A0378D776
      10FF9F570CDB0000001214149EDE1B1BD1FF1B1BD1FF1515A3E1000000159F58
      0CDCD77610FFD77610FF00000000000000000000000000000000000000000000
      00001D1D1D82717171FF717171FF717171FF717171FF717171FF717171FF1D1D
      1D82000000000000000000000000000000000000000000000000717171FF0000
      000014B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF00000000717171FF00000000000000000000000000000000626262ED7171
      71FF717171FF717171FF717171FF555555DE0101011F00000000636363EF7171
      71FF717171FF555555DE00000000000000000000000000000000000000002F1A
      037820120264070735811B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF07073986190E
      0258D77610FFD77610FF00000000000000000000000000000000000000001D1D
      1D82717171FF717171FF717171FF717171FF717171FF717171FF717171FF7171
      71FF1D1D1D820000000000000000000000000000000000000000717171FF0000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000717171FF00000000000000000000000000000000000000000000
      000000000000717171FF00000000000000000000000000000000717171FF7171
      71FF555555DE0101011F00000000000000000000000000000000000000000000
      0000000000031616A9E61B1BD1FF01010A38000008321B1BD1FF1717B2EB0000
      00002F1A0378D77610FF000000000000000000000000000000001D1D1D827171
      71FF717171FF717171FF717171FF717171FF717171FF717171FF717171FF7171
      71FF717171FF1D1D1D8200000000000000000000000000000000717171FF0000
      0000000000003F3F3FBF3F3F3FBF3F3F3FBF3F3F3FBF3F3F3FBF3F3F3FBF0000
      000000000000717171FF00000000000000000000000000000000000000000000
      000000000000717171FF00000000000000000000000000000000717171FF5555
      55DE0101011F0000000000000000000000000000000000000000000000000000
      0000000000001818B4ED1B1BD1FF01010B3D01010A381B1BD1FF1818BCF20000
      0000000000002F1A037800000000000000000000000000000000717171FF7171
      71FF717171FF717171FF717171FF717171FF717171FF717171FF717171FF7171
      71FF717171FF717171FF00000000000000000000000000000000717171FF0000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000717171FF00000000000000000000000000000000000000000000
      000000000000626262ED717171FF717171FF717171FF717171FF555555DE0101
      011F000000000000000000000000000000000000000000000000000000000000
      00000000000008083F8D1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF090944930000
      0000000000000000000000000000000000000000000000000000717171FF7171
      71FF717171FF717171FF717171FF717171FF717171FF717171FF717171FF7171
      71FF717171FF717171FF00000000000000000000000000000000646464F07171
      71FF717171FF717171FF717171FF717171FF717171FF717171FF717171FF7171
      71FF717171FF666666F200000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000608083F8D1818B4ED1818B5ED09094290000000070000
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
      00000000000000000000000000000000000000000000B57936FFB57936FFB579
      36FFB57936FFB57936FFB57936FFB57936FFB57936FFB57936FFB57936FFB579
      36FFB57936FFB57936FFB57936FF000000000000000000000000000000000000
      00000000021A07073A88131392D51B1BC9FB1B1BCAFB141494D708083C8A0000
      021B000000000000000000000000000000000000000000000000666666F27171
      71FF717171FF717171FF717171FF717171FF717171FF717171FF717171FF7171
      71FF717171FF686868F500000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000B57936FFB57936FFFFFF
      FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
      FFFFFFFFFFFFB57936FFB57936FF000000000000000000000000000000000303
      18581919BCF21B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1919
      BDF303031A5C0000000000000000000000000000000000000000717171FF7171
      71FF717171FF717171FF717171FF717171FF717171FF717171FF717171FF7171
      71FF717171FF717171FF0000000000000000000000000002031E0B638FBF14B1
      FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF14B1FFFF073F5C99000000000000000000000000B57936FFB57936FFFFFF
      FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
      FFFFFFFFFFFFB57936FFB57936FF000000000000000000000000030318571B1B
      CEFD1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BCFFE03031A5C00000000000000000000000000000000717171FF7171
      71FF000000000000000000000000000000000000000000000000000000000000
      0000717171FF717171FF00000000000000000000000004253676010E144814B1
      FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF14B1FFFF14AAF5FA0002031E0000000000000000B57936FFB57936FFFFFF
      FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
      FFFFFFFFFFFFB57936FFB57936FF0000000000000000000001181818BAF11B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1919BDF30000021B000000000000000000000000717171FF7171
      71FF000000000000000000000000000000000000000000000000000000000000
      0000717171FF717171FF0000000000000000000000000B5F87BA000101140D75
      A9D014B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF14B1FFFF14B1FFFF0637508F0000000000000000B57936FFB57936FFFFFF
      FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
      FFFFFFFFFFFFB57936FFB57936FF0000000000000000070738851B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF08083C8A000000000000000000000000717171FF7171
      71FF000000000000000000000000000000000000000000000000000000000000
      0000717171FF717171FF0000000000000000000000000B638FBF031C28660215
      1E5914B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF14B1FFFF14B1FFFF12A1E7F30000011200000000B57936FFB57936FFFFFF
      FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
      FFFFFFFFFFFFB57936FFB57936FF000000000000000012128DD21B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF131394D7000000000000000000000000717171FF7171
      71FF717171FF717171FF717171FF717171FF717171FF00000000000000000000
      000000000000000000000000000000000000000000000B638FBF0A577DB30000
      000E0F86C1DE14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF14B1FFFF14B1FFFF14B1FFFF04293B7B00000000B57936FFB57936FFFFFF
      FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
      FFFFFFFFFFFFB57936FFB57936FF00000000000000001919C2F61B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1A1ACAFB000000000000000000000000717171FF7171
      71FF717171FF717171FF717171FF717171FF717171FF00000000C16A0FF2D776
      10FFD77610FFD77610FFD77610FFC66D0FF5000000000B638FBF0B638FBF0214
      1D57031E2B6A14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1FFFF14B1
      FFFF14B1FFFF14B1FFFF14B1FFFF108CCAE300000000B57936FFB57936FFFFFF
      FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
      FFFFFFFFFFFFB57936FFB57936FF00000000000000001919C1F51B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1A1AC9FB000000000000000000000000717171FF7171
      71FF000000000000000000000000000000000000000000000000D77610FF0000
      0000000000000000000000000000D77610FF000000000B638FBF0B638FBF094F
      71AA000001120000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000B57936FFB57936FFB579
      36FFB57936FFB57936FFB57936FFB57936FFB57936FFB57936FFB57936FFB579
      36FFB57936FFB57936FFB57936FF000000000000000012128AD01B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF131392D5000000000000000000000000717171FF7171
      71FF00000000717171FF717171FF717171FF717171FF00000000D77610FF0000
      0000000000000000000000000000D77610FF000000000B638FBF0B638FBF0B63
      8FBF0B638FBF0B638FBF0B638FBF0B638FBF0B638FBF0B638FBF0B638FBF0B63
      8FBF0B638FBF00000000000000000000000000000000B57936FFB57936FFE1CA
      AFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CA
      AFFFB57936FFB57936FFB57936FF0000000000000000070736831B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1B1BD1FF07073A88000000000000000000000000717171FF7171
      71FF00000000717171FF00000000717171FF717171FF00000000D77610FF0000
      0000000000000000000000000000D77610FF000000000B638FBF0B638FBF0B63
      8FBF0B638FBF0B638FBF0B638FBF0B638FBF0B638FBF0B638FBF0B638FBF0B63
      8FBF0A5980B500000000000000000000000000000000B57936FFB57936FFE1CA
      AFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFB57936FFE1CA
      AFFFB57936FFB57936FFB57936FF0000000000000000000001171818B8F01B1B
      D1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BD1FF1919BCF20000021A000000000000000000000000717171FF7171
      71FF00000000717171FF00000000717171FF717171FF00000000D77610FF0000
      0000000000000000000000000000D77610FF000000000B638FBF0B638FBF0B63
      8FBF0B638FBF0B638FBF00000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000B57936FFB57936FFE1CA
      AFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFB57936FFE1CA
      AFFFB57936FFB57936FFB57936FF000000000000000000000000020216531B1B
      CDFD1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1B
      D1FF1B1BCEFD0303185800000000000000000000000000000000646464F07171
      71FF00000000717171FF717171FF717171FF717171FF00000000D77610FFD776
      10FFC66D0FF50000000000000000D77610FF000000000A577DB30B638FBF0B63
      8FBF0B638FBF0A5980B500000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000B57936FFB57936FFE1CA
      AFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFB57936FFE1CA
      AFFFB57936FFB57936FF2B1D0D7D000000000000000000000000000000000202
      16531818B8F01B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1B1BD1FF1818
      BAF1030318570000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000331C037DD776
      10FFD77610FF0000000000000000D77610FF0000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000B57936FFB57936FFE1CA
      AFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFE1CAAFFFB57936FFE1CA
      AFFFB57936FF2B1D0D7D00000000000000000000000000000000000000000000
      0000000001170707368312128AD01919C1F51919C2F612128CD1070737840000
      0118000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000000000000000000000000000331C
      037DD77610FFD77610FFD77610FFC16A0FF20000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000424D3E000000000000003E000000
      2800000040000000500000000100010000000000800200000000000000000000
      000000000000000000000000FFFFFF0000000000000000000000000000000000
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
      000000000000}
    DesignInfo = 24641856
    ImageInfo = <
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
          73706163653D227072657365727665223E262331333B262331303B3C706F6C79
          676F6E2066696C6C3D22233337374142352220706F696E74733D22322C322032
          2C33302033302C33302033302C362032362C3220222F3E0D0A3C726563742078
          3D22362220793D223134222066696C6C3D222346464646464622207769647468
          3D22323022206865696768743D223134222F3E0D0A3C7265637420783D223622
          20793D223222206F7061636974793D22302E36222066696C6C3D222346464646
          46462220656E61626C652D6261636B67726F756E643D226E6577202020202220
          77696474683D22313822206865696768743D223130222F3E0D0A3C7265637420
          783D2232302220793D2232222066696C6C3D2223333737414235222077696474
          683D223222206865696768743D2238222F3E0D0A3C2F7376673E0D0A}
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
          303B3C7374796C6520747970653D22746578742F6373732220786D6C3A737061
          63653D227072657365727665223E2E426C61636B7B66696C6C3A233732373237
          323B7D262331333B262331303B2623393B2E426C75657B66696C6C3A23313137
          3744373B7D3C2F7374796C653E0D0A3C7061746820636C6173733D22426C6163
          6B2220643D224D32342C323076364838762D36683130762D3448385636483543
          342E342C362C342C362E342C342C3776323263302C302E362C302E342C312C31
          2C3168323263302E362C302C312D302E342C312D31762D394832347A204D3138
          2C36682D387638683856367A20202623393B204D31342C3132682D3256386832
          5631327A222F3E0D0A3C7061746820636C6173733D22426C75652220643D224D
          33312C32682D35682D326C2D342C347632763963302C302E362C302E342C312C
          312C3168313063302E362C302C312D302E342C312D3156334333322C322E342C
          33312E362C322C33312C327A204D33302C3136682D385638683320202623393B
          63302E362C302C312D302E342C312D31563468345631367A222F3E0D0A3C2F73
          76673E0D0A}
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
          303B3C7374796C6520747970653D22746578742F637373223E2E426C61636B7B
          66696C6C3A233732373237323B7D3C2F7374796C653E0D0A3C7061746820636C
          6173733D22426C61636B2220643D224D32312C32483131632D302E352C302D31
          2C302E352D312C317635483543342E352C382C342C382E352C342C3976323063
          302C302E352C302E352C312C312C3168313663302E352C302C312D302E352C31
          2D31762D35683563302E352C302C312D302E352C312D3120202623393B56394C
          32312C327A204D32302C323848365631306838763563302C302E352C302E352C
          312C312C3168355632387A204D32362C3232682D34762D376C2D372D37682D33
          56346838763563302C302E352C302E352C312C312C3168355632327A222F3E0D
          0A3C2F7376673E0D0A}
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
          303B3C7374796C6520747970653D22746578742F6373732220786D6C3A737061
          63653D227072657365727665223E2E59656C6C6F777B66696C6C3A2346464231
          31353B7D262331333B262331303B2623393B2E5265647B66696C6C3A23443131
          4331433B7D262331333B262331303B2623393B2E426C61636B7B66696C6C3A23
          3732373237323B7D262331333B262331303B2623393B2E426C75657B66696C6C
          3A233131373744373B7D262331333B262331303B2623393B2E57686974657B66
          696C6C3A234646464646463B7D262331333B262331303B2623393B2E47726565
          6E7B66696C6C3A233033394332333B7D262331333B262331303B2623393B2E73
          74307B6F7061636974793A302E37353B7D262331333B262331303B2623393B2E
          7374317B6F7061636974793A302E353B7D262331333B262331303B2623393B2E
          7374327B6F7061636974793A302E32353B7D262331333B262331303B2623393B
          2E7374337B66696C6C3A234646423131353B7D3C2F7374796C653E0D0A3C672F
          3E0D0A3C672069643D2247656F506F696E4D617073223E0D0A09093C70617468
          20636C6173733D225265642220643D224D31362C30632D332E332C302D362C32
          2E372D362C3673362C31302C362C313073362D362E372C362D31305331392E33
          2C302C31362C307A204D31362C38632D312E312C302D322D302E392D322D3273
          302E392D322C322D3273322C302E392C322C3220202623393B2623393B533137
          2E312C382C31362C387A222F3E0D0A09093C7061746820636C6173733D22426C
          75652220643D224D32332E342C382E36632D302E382C312E392D322E312C342D
          332E342C352E3776302E355631397631302E326C2D382D38563139762D342E37
          632D312E352D312E392D332E312D342E342D332E372D362E364C342C31327632
          306C382D386C382C386C382D38563420202623393B2623393B4C32332E342C38
          2E367A222F3E0D0A093C2F673E0D0A3C2F7376673E0D0A}
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
          303B3C7374796C6520747970653D22746578742F637373223E2E426C61636B7B
          66696C6C3A233732373237323B7D3C2F7374796C653E0D0A3C672069643D224D
          617374657246696C746572223E0D0A09093C706F6C79676F6E20636C6173733D
          22426C61636B2220706F696E74733D22342C322032382C322032382C36203138
          2C31362031382C32362031342C33302031342C313620342C3620222F3E0D0A09
          3C2F673E0D0A3C2F7376673E0D0A}
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
          303B3C7374796C6520747970653D22746578742F6373732220786D6C3A737061
          63653D227072657365727665223E2E426C61636B7B66696C6C3A233732373237
          323B7D262331333B262331303B2623393B2E59656C6C6F777B66696C6C3A2346
          46423131353B7D262331333B262331303B2623393B2E7374307B6F7061636974
          793A302E37353B7D3C2F7374796C653E0D0A3C673E0D0A09093C673E0D0A0909
          093C7061746820636C6173733D22426C61636B2220643D224D32372C32483543
          342E342C322C342C322E342C342C3376323663302C302E362C302E342C312C31
          2C3168323263302E362C302C312D302E342C312D3156334332382C322E342C32
          372E362C322C32372C327A204D32362C3238483656346832305632387A222F3E
          0D0A09093C2F673E0D0A09093C673E0D0A0909093C7061746820636C6173733D
          22426C61636B2220643D224D32372C32483543342E342C322C342C322E342C34
          2C3376323663302C302E362C302E342C312C312C3168323263302E362C302C31
          2D302E342C312D3156334332382C322E342C32372E362C322C32372C327A204D
          32362C3238483656346832305632387A222F3E0D0A09093C2F673E0D0A093C2F
          673E0D0A3C7061746820636C6173733D2259656C6C6F772220643D224D382C31
          307638683136762D3848387A204D32322C3136483130762D346831325631367A
          222F3E0D0A3C6720636C6173733D22737430223E0D0A09093C7265637420783D
          2231302220793D22362220636C6173733D22426C61636B222077696474683D22
          313222206865696768743D2232222F3E0D0A09093C7265637420783D22313022
          20793D2232302220636C6173733D22426C61636B222077696474683D22313222
          206865696768743D2232222F3E0D0A09093C7265637420783D2231302220793D
          2232342220636C6173733D22426C61636B222077696474683D22313222206865
          696768743D2232222F3E0D0A093C2F673E0D0A3C2F7376673E0D0A}
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
          303B3C7374796C6520747970653D22746578742F6373732220786D6C3A737061
          63653D227072657365727665223E2E426C61636B7B66696C6C3A233732373237
          323B7D262331333B262331303B2623393B2E477265656E7B66696C6C3A233033
          394332333B7D262331333B262331303B2623393B2E59656C6C6F777B66696C6C
          3A234646423131353B7D262331333B262331303B2623393B2E426C75657B6669
          6C6C3A233131373744373B7D262331333B262331303B2623393B2E5265647B66
          696C6C3A234431314331433B7D3C2F7374796C653E0D0A3C672069643D224D61
          70506F696E746572223E0D0A09093C7061746820636C6173733D225265642220
          643D224D31362C324331302E352C322C362C362E352C362C313263302C352E35
          2C31302C31382C31302C31387331302D31322E352C31302D31384332362C362E
          352C32312E352C322C31362C327A204D31362C3136632D322E322C302D342D31
          2E382D342D3420202623393B2623393B63302D322E322C312E382D342C342D34
          73342C312E382C342C344332302C31342E322C31382E322C31362C31362C3136
          7A222F3E0D0A093C2F673E0D0A3C2F7376673E0D0A}
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
          303B3C7374796C6520747970653D22746578742F6373732220786D6C3A737061
          63653D227072657365727665223E2E426C61636B7B66696C6C3A233733373337
          343B7D262331333B262331303B2623393B2E59656C6C6F777B66696C6C3A2346
          43423031423B7D262331333B262331303B2623393B2E477265656E7B66696C6C
          3A233132394334393B7D262331333B262331303B2623393B2E426C75657B6669
          6C6C3A233338374342373B7D262331333B262331303B2623393B2E5265647B66
          696C6C3A234430323132373B7D262331333B262331303B2623393B2E57686974
          657B66696C6C3A234646464646463B7D262331333B262331303B2623393B2E73
          74307B6F7061636974793A302E353B7D262331333B262331303B2623393B2E73
          74317B6F7061636974793A302E37353B7D262331333B262331303B2623393B2E
          7374327B6F7061636974793A302E32353B7D262331333B262331303B2623393B
          2E7374337B646973706C61793A6E6F6E653B66696C6C3A233733373337343B7D
          3C2F7374796C653E0D0A3C706F6C79676F6E20636C6173733D22426C61636B22
          20706F696E74733D2232342C32342032342C32322E3520372E352C3620362C36
          20362C372E352032322E352C323420222F3E0D0A3C7061746820636C6173733D
          22426C75652220643D224D372C32483343322E352C322C322C322E352C322C33
          763463302C302E352C302E352C312C312C31683463302E352C302C312D302E35
          2C312D31563343382C322E352C372E352C322C372C327A204D362C3648345634
          683256367A204D32372C3232682D3420202623393B632D302E352C302D312C30
          2E352D312C31763463302C302E352C302E352C312C312C31683463302E352C30
          2C312D302E352C312D31762D344332382C32322E352C32372E352C32322C3237
          2C32327A204D32362C3236682D32762D3268325632367A222F3E0D0A3C2F7376
          673E0D0A}
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
          303B3C7374796C6520747970653D22746578742F6373732220786D6C3A737061
          63653D227072657365727665223E2E426C61636B7B66696C6C3A233732373237
          323B7D262331333B262331303B2623393B2E59656C6C6F777B66696C6C3A2346
          46423131353B7D262331333B262331303B2623393B2E426C75657B66696C6C3A
          233131373744373B7D262331333B262331303B2623393B2E477265656E7B6669
          6C6C3A233033394332333B7D262331333B262331303B2623393B2E5265647B66
          696C6C3A234431314331433B7D262331333B262331303B2623393B2E57686974
          657B66696C6C3A234646464646463B7D262331333B262331303B2623393B2E73
          74307B6F7061636974793A302E37353B7D262331333B262331303B2623393B2E
          7374317B6F7061636974793A302E353B7D262331333B262331303B2623393B2E
          7374327B6F7061636974793A302E32353B7D3C2F7374796C653E0D0A3C672069
          643D224164644E657744617461536F75726365223E0D0A09093C706174682063
          6C6173733D2259656C6C6F772220643D224D342C3130563663302D322E322C34
          2E352D342C31302D347331302C312E382C31302C34763463302C322E322D342E
          352C342D31302C3453342C31322E322C342C31307A204D31342C323063332E33
          2C302C362E322D302E362C382D312E365631366832762D3420202623393B2623
          393B63302C322E322D342E352C342D31302C3453342C31342E322C342C313276
          3443342C31382E322C382E352C32302C31342C32307A204D31382C32312E3763
          2D312E322C302E322D322E362C302E332D342C302E33632D352E352C302D3130
          2D312E382D31302D34763463302C322E322C342E352C342C31302C3420202623
          393B2623393B63312E342C302C322E382D302E312C342D302E335632312E377A
          222F3E0D0A09093C706F6C79676F6E20636C6173733D22477265656E2220706F
          696E74733D2233322C32322032382C32322032382C31382032342C3138203234
          2C32322032302C32322032302C32362032342C32362032342C33302032382C33
          302032382C32362033322C3236202623393B222F3E0D0A093C2F673E0D0A3C2F
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
          303B3C7374796C6520747970653D22746578742F6373732220786D6C3A737061
          63653D227072657365727665223E2E426C61636B7B66696C6C3A233732373237
          323B7D262331333B262331303B2623393B2E59656C6C6F777B66696C6C3A2346
          46423131353B7D262331333B262331303B2623393B2E426C75657B66696C6C3A
          233131373744373B7D262331333B262331303B2623393B2E477265656E7B6669
          6C6C3A233033394332333B7D262331333B262331303B2623393B2E5265647B66
          696C6C3A234431314331433B7D262331333B262331303B2623393B2E57686974
          657B66696C6C3A234646464646463B7D262331333B262331303B2623393B2E73
          74307B6F7061636974793A302E37353B7D262331333B262331303B2623393B2E
          7374317B6F7061636974793A302E353B7D262331333B262331303B2623393B2E
          7374327B6F7061636974793A302E32353B7D3C2F7374796C653E0D0A3C672069
          643D2247726F75704669656C64436F6C6C656374696F6E223E0D0A09093C7061
          746820636C6173733D22426C75652220643D224D32312C31324835632D302E36
          2C302D312D302E342D312D31563363302D302E352C302E342D312C312D316831
          3663302E352C302C312C302E352C312C3176384332322C31312E362C32312E35
          2C31322C32312C31327A204D33312C313448313520202623393B2623393B632D
          302E352C302D312C302E352D312C3176302E3963302E312C302E312C302E322C
          302E312C302E332C302E326C312E362C312E3663302E372C302E372C302E382C
          312E382C302E322C322E366C2D302E342C302E366C302E372C302E3263302E39
          2C302E322C312E362C312C312E362C32763168313320202623393B2623393B63
          302E352C302C312D302E352C312D31762D384333322C31342E352C33312E352C
          31342C33312C31347A222F3E0D0A09093C7061746820636C6173733D22426C61
          636B2220643D224D31362C3235762D326C2D322E352D302E36632D302E312D30
          2E342D302E332D302E382D302E352D312E326C312E352D322E316C2D312E362D
          312E364C31302E382C3139632D302E342D302E322D302E382D302E342D312E32
          2D302E354C392C3136483720202623393B2623393B6C2D302E362C322E354336
          2C31382E362C352E362C31382E382C352E322C31396C2D322E312D312E356C2D
          312E362C312E364C332C32312E32632D302E322C302E342D302E342C302E382D
          302E352C312E324C302C323376326C322E352C302E3643322E362C32362C322E
          382C32362E342C332C32362E3820202623393B2623393B6C2D312E352C322E31
          6C312E362C312E364C352E322C323963302E342C302E322C302E382C302E342C
          312E322C302E354C372C333268326C302E362D322E3563302E342D302E312C30
          2E382D302E332C312E322D302E356C322E312C312E356C312E362D312E364C31
          332C32362E3820202623393B2623393B63302E322D302E342C302E342D302E38
          2C302E352D312E324C31362C32357A204D382C3236632D312E312C302D322D30
          2E392D322D3263302D312E312C302E392D322C322D3263312E312C302C322C30
          2E392C322C324331302C32352E312C392E312C32362C382C32367A222F3E0D0A
          093C2F673E0D0A3C2F7376673E0D0A}
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
          303B3C7374796C6520747970653D22746578742F6373732220786D6C3A737061
          63653D227072657365727665223E2E477265656E7B66696C6C3A233033394332
          333B7D262331333B262331303B2623393B2E426C61636B7B66696C6C3A233732
          373237323B7D262331333B262331303B2623393B2E5265647B66696C6C3A2344
          31314331433B7D262331333B262331303B2623393B2E59656C6C6F777B66696C
          6C3A234646423131353B7D262331333B262331303B2623393B2E426C75657B66
          696C6C3A233131373744373B7D262331333B262331303B2623393B2E57686974
          657B66696C6C3A234646464646463B7D262331333B262331303B2623393B2E73
          74307B6F7061636974793A302E353B7D262331333B262331303B2623393B2E73
          74317B6F7061636974793A302E37353B7D3C2F7374796C653E0D0A3C67206964
          3D22496E73657274427562626C654D6170223E0D0A09093C7061746820636C61
          73733D22426C75652220643D224D32312E372C31302E3363322E352C302E372C
          342E332C332C342E332C352E3763302C332E332D322E372C362D362C3676372E
          326C2D382D38762D372E33632D322E352D302E342D342E362D322E312D352E35
          2D342E344C342C31327632306C382D386C382C3820202623393B2623393B6C38
          2D3856344C32312E372C31302E337A222F3E0D0A09093C636972636C6520636C
          6173733D22477265656E222063783D223133222063793D22372220723D223522
          2F3E0D0A09093C636972636C6520636C6173733D2259656C6C6F77222063783D
          223230222063793D2231362220723D2234222F3E0D0A093C2F673E0D0A3C2F73
          76673E0D0A}
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
          303B3C7374796C6520747970653D22746578742F6373732220786D6C3A737061
          63653D227072657365727665223E2E59656C6C6F777B66696C6C3A2346464231
          31353B7D262331333B262331303B2623393B2E5265647B66696C6C3A23443131
          4331433B7D262331333B262331303B2623393B2E426C75657B66696C6C3A2331
          31373744373B7D262331333B262331303B2623393B2E477265656E7B66696C6C
          3A233033394332333B7D262331333B262331303B2623393B2E426C61636B7B66
          696C6C3A233732373237323B7D262331333B262331303B2623393B2E57686974
          657B66696C6C3A234646464646463B7D262331333B262331303B2623393B2E73
          74307B6F7061636974793A302E353B7D262331333B262331303B2623393B2E73
          74317B646973706C61793A6E6F6E653B7D262331333B262331303B2623393B2E
          7374327B646973706C61793A696E6C696E653B66696C6C3A233033394332333B
          7D262331333B262331303B2623393B2E7374337B646973706C61793A696E6C69
          6E653B66696C6C3A234431314331433B7D262331333B262331303B2623393B2E
          7374347B646973706C61793A696E6C696E653B66696C6C3A233732373237323B
          7D3C2F7374796C653E0D0A3C672069643D2244657461696C6564223E0D0A0909
          3C7061746820636C6173733D22426C75652220643D224D382C38483656366832
          56387A204D382C31304836763268325631307A204D382C313448367632683256
          31347A204D382C31384836763268325631387A204D382C323248367632683256
          32327A222F3E0D0A09093C7061746820636C6173733D22426C61636B2220643D
          224D322C323856326832327631322E3363302E372C302E322C312E342C302E35
          2C322C302E38563163302D302E352D302E352D312D312D31483143302E352C30
          2C302C302E352C302C3176323863302C302E352C302E352C312C312C31683231
          20202623393B2623393B632D322C302D332E392D302E382D352E332D3248327A
          222F3E0D0A09093C7061746820636C6173733D22426C75652220643D224D3331
          2E362C32392E394C32372C32352E3363302E362D302E392C312D322E312C312D
          332E3363302D332E332D322E372D362D362D36732D362C322E372D362C367332
          2E372C362C362C3663312E322C302C322E332D302E342C332E332D316C342E36
          2C342E3620202623393B2623393B63302E352C302E352C312E332C302E352C31
          2E372C304333322E312C33312E322C33322E312C33302E342C33312E362C3239
          2E397A204D32322C3236632D322E322C302D342D312E382D342D3473312E382D
          342C342D3473342C312E382C342C345332342E322C32362C32322C32367A222F
          3E0D0A09093C6720636C6173733D22737430223E0D0A0909093C706174682063
          6C6173733D22426C61636B2220643D224D31362E372C3136483130762D326831
          3076302E334331382E382C31342E362C31372E362C31352E322C31362E372C31
          367A204D32302C36483130763268313056367A204D32302C3130483130763268
          31305631307A204D31342C3232682D34763268342E3320202623393B2623393B
          2623393B4331342E312C32332E342C31342C32322E372C31342C32327A204D31
          352E312C3138483130763268342E334331342E342C31392E332C31342E372C31
          382E362C31352E312C31387A222F3E0D0A09093C2F673E0D0A093C2F673E0D0A
          3C2F7376673E0D0A}
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
          303B3C7374796C6520747970653D22746578742F637373223E2E426C75657B66
          696C6C3A233131373744373B7D3C2F7374796C653E0D0A3C7061746820636C61
          73733D22426C75652220643D224D33302C3138762D346C2D342E342D302E3763
          2D302E322D302E382D302E352D312E352D302E392D322E316C322E362D332E36
          6C2D322E382D322E386C2D332E362C322E36632D302E372D302E342D312E342D
          302E372D322E312D302E394C31382C32682D3420202623393B6C2D302E372C34
          2E34632D302E382C302E322D312E352C302E352D322E312C302E394C372E352C
          342E374C342E372C372E356C322E362C332E36632D302E342C302E372D302E37
          2C312E342D302E392C322E314C322C313476346C342E342C302E3763302E322C
          302E382C302E352C312E352C302E392C322E3120202623393B6C2D322E362C33
          2E366C322E382C322E386C332E362D322E3663302E372C302E342C312E342C30
          2E372C322E312C302E394C31342C333068346C302E372D342E3463302E382D30
          2E322C312E352D302E352C322E312D302E396C332E362C322E366C322E382D32
          2E386C2D322E362D332E3620202623393B63302E342D302E372C302E372D312E
          342C302E392D322E314C33302C31387A204D31362C3230632D322E322C302D34
          2D312E382D342D3473312E382D342C342D3473342C312E382C342C345331382E
          322C32302C31362C32307A222F3E0D0A3C2F7376673E0D0A}
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
          303B3C7374796C6520747970653D22746578742F6373732220786D6C3A737061
          63653D227072657365727665223E2E59656C6C6F777B66696C6C3A2346464231
          31353B7D262331333B262331303B2623393B2E5265647B66696C6C3A23443131
          4331433B7D262331333B262331303B2623393B2E426C75657B66696C6C3A2331
          31373744373B7D262331333B262331303B2623393B2E477265656E7B66696C6C
          3A233033394332333B7D262331333B262331303B2623393B2E426C61636B7B66
          696C6C3A233732373237323B7D262331333B262331303B2623393B2E57686974
          657B66696C6C3A234646464646463B7D262331333B262331303B2623393B2E73
          74307B6F7061636974793A302E353B7D262331333B262331303B2623393B2E73
          74317B646973706C61793A6E6F6E653B7D262331333B262331303B2623393B2E
          7374327B646973706C61793A696E6C696E653B66696C6C3A233033394332333B
          7D262331333B262331303B2623393B2E7374337B646973706C61793A696E6C69
          6E653B66696C6C3A234431314331433B7D262331333B262331303B2623393B2E
          7374347B646973706C61793A696E6C696E653B66696C6C3A233732373237323B
          7D3C2F7374796C653E0D0A3C672069643D224C6F77496D706F7274616E636522
          3E0D0A09093C7061746820636C6173733D22426C75652220643D224D31362C32
          43382E332C322C322C382E332C322C313673362E332C31342C31342C31347331
          342D362E332C31342D31345332332E372C322C31362C327A204D31362C32346C
          2D362D3668345638683476313068344C31362C32347A222F3E0D0A093C2F673E
          0D0A3C2F7376673E0D0A}
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
          303B3C7374796C6520747970653D22746578742F6373732220786D6C3A737061
          63653D227072657365727665223E2E477265656E7B66696C6C3A233033394332
          333B7D262331333B262331303B2623393B2E426C61636B7B66696C6C3A233732
          373237323B7D262331333B262331303B2623393B2E5265647B66696C6C3A2344
          31314331433B7D262331333B262331303B2623393B2E59656C6C6F777B66696C
          6C3A234646423131353B7D262331333B262331303B2623393B2E426C75657B66
          696C6C3A233131373744373B7D262331333B262331303B2623393B2E57686974
          657B66696C6C3A234646464646463B7D262331333B262331303B2623393B2E73
          74307B6F7061636974793A302E353B7D262331333B262331303B2623393B2E73
          74317B6F7061636974793A302E37353B7D3C2F7374796C653E0D0A3C67206964
          3D22496E736572745472656556696577223E0D0A09093C7061746820636C6173
          733D2259656C6C6F772220643D224D31332C38483543342E342C382C342C372E
          362C342C37563363302D302E352C302E342D312C312D31683863302E362C302C
          312C302E352C312C3176344331342C372E362C31332E362C382C31332C387A20
          4D32362C3137762D3420202623393B2623393B63302D302E362D302E352D312D
          312D31682D38632D302E352C302D312C302E342D312C31763463302C302E352C
          302E352C312C312C3168384332352E352C31382C32362C31372E352C32362C31
          377A204D32362C3237762D3463302D302E352D302E352D312D312D31682D3863
          2D302E352C302D312C302E352D312C3120202623393B2623393B763463302C30
          2E352C302E352C312C312C3168384332352E352C32382C32362C32372E352C32
          362C32377A222F3E0D0A09093C706F6C79676F6E20636C6173733D22426C6163
          6B2220706F696E74733D2231342C31362031342C31342031302C31342031302C
          313020382C313020382C32362031342C32362031342C32342031302C32342031
          302C3136202623393B222F3E0D0A093C2F673E0D0A3C2F7376673E0D0A}
      end
      item
        ImageClass = 'TdxSmartImage'
        Image.Data = {
          3C3F786D6C2076657273696F6E3D22312E302220656E636F64696E673D225554
          462D38223F3E0D0A3C7376672076657273696F6E3D22312E31222069643D2243
          7573746F6D697A654D657267654669656C642220786D6C6E733D22687474703A
          2F2F7777772E77332E6F72672F323030302F7376672220786D6C6E733A786C69
          6E6B3D22687474703A2F2F7777772E77332E6F72672F313939392F786C696E6B
          2220783D223070782220793D22307078222076696577426F783D223020302033
          3220333222207374796C653D22656E61626C652D6261636B67726F756E643A6E
          6577203020302033322033323B2220786D6C3A73706163653D22707265736572
          7665223E262331333B262331303B3C7374796C6520747970653D22746578742F
          6373732220786D6C3A73706163653D227072657365727665223E2E426C61636B
          7B66696C6C3A233732373237323B7D262331333B262331303B2623393B2E426C
          75657B66696C6C3A233131373744373B7D262331333B262331303B2623393B2E
          59656C6C6F777B66696C6C3A234646423131353B7D3C2F7374796C653E0D0A3C
          7265637420783D22362220793D2231302220636C6173733D2259656C6C6F7722
          2077696474683D22313422206865696768743D2232222F3E0D0A3C7061746820
          636C6173733D22426C75652220643D224D33312E352C32382E396C2D362E312D
          362E314332352E382C32312E392C32362C32312C32362C323063302D332E332D
          322E372D362D362D36632D312C302D312E392C302E322D322E372C302E376C34
          2E322C342E3220202623393B63302E372C302E372C302E372C312E392C302C32
          2E36632D302E372C302E372D312E392C302E372D322E362C306C2D342E322D34
          2E324331342E322C31382E312C31342C31392C31342C323063302C332E332C32
          2E372C362C362C3663312C302C312E392D302E322C322E372D302E376C362E31
          2C362E3120202623393B63302E372C302E372C312E392C302E372C322E362C30
          4333322E322C33302E382C33322E322C32392E362C33312E352C32382E397A22
          2F3E0D0A3C7061746820636C6173733D22426C61636B2220643D224D32342E36
          2C33304831632D302E352C302D312D302E352D312D31563163302D302E352C30
          2E352D312C312D3168323463302E352C302C312C302E352C312C317631332E37
          632D302E362D302E372D312E322D312E322D322D312E36563248327632366832
          302E3620202623393B4C32342E362C33307A204D32302C364836763268313456
          367A204D31362C3134483676326831305631347A204D31322C32324836763268
          365632327A204D31322C31384836763268365631387A222F3E0D0A3C2F737667
          3E0D0A}
      end>
  end
  object SaveDialog1: TSaveDialog
    Left = 304
    Top = 264
  end
  object dxSkinController1: TdxSkinController
    SkinName = 'Basic'
    SkinPaletteName = 'Violet Dark'
    Left = 984
    Top = 168
  end
  object cxGridPopupMenu1: TcxGridPopupMenu
    Grid = GridPcap
    PopupMenus = <>
    Left = 664
    Top = 456
  end
  object PopupGrid: TdxBarPopupMenu
    BarManager = dxBarManager1
    ItemLinks = <
      item
        Visible = True
        ItemName = 'BSavePCAP'
      end
      item
        Visible = True
        ItemName = 'BSaevGrid'
      end
      item
        BeginGroup = True
        Visible = True
        ItemName = 'BCopyGrid'
      end
      item
        BeginGroup = True
        Visible = True
        ItemName = 'BQuickFilter'
      end
      item
        BeginGroup = True
        Visible = True
        ItemName = 'BMap'
      end
      item
        Visible = True
        ItemName = 'BSubWhoise'
      end
      item
        Visible = True
        ItemName = 'BFlow'
      end
      item
        Visible = True
        ItemName = 'BRTPCall'
      end>
    UseOwnFont = False
    Left = 344
    Top = 448
    PixelsPerInch = 96
  end
  object FDConnection1: TFDConnection
    Left = 544
    Top = 336
  end
  object dxCalloutPopup1: TdxCalloutPopup
    Left = 760
    Top = 544
  end
  object dxBarPopupMenu1: TdxBarPopupMenu
    BarManager = dxBarManager1
    ItemLinks = <
      item
        Visible = True
        ItemName = 'BCopyTreeList'
      end
      item
        Visible = True
        ItemName = 'BFilterByLabel'
      end>
    UseOwnFont = False
    Left = 984
    Top = 334
    PixelsPerInch = 96
  end
  object dxSaveFileDialog1: TdxSaveFileDialog
    Left = 408
    Top = 272
  end
  object dxOpenFileDialog1: TdxOpenFileDialog
    Left = 480
    Top = 216
  end
  object PSSettings: TcxPropertiesStore
    Active = False
    Components = <
      item
        Component = TActiveGEOIP
        Properties.Strings = (
          'EditValue')
      end
      item
        Component = TActiveVerobse
        Properties.Strings = (
          'EditValue')
      end>
    StorageName = 'Config\AppSettings.ini'
    Left = 632
    Top = 232
  end
end
