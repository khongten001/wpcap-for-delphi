object Form2: TForm2
  Left = 0
  Top = 0
  Caption = 'PCAP Analisys'
  ClientHeight = 666
  ClientWidth = 1201
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object Label1: TLabel
    AlignWithMargins = True
    Left = 3
    Top = 3
    Width = 1195
    Height = 13
    Align = alTop
    Caption = 'Filter:'
    ExplicitWidth = 28
  end
  object Button1: TButton
    Left = 0
    Top = 641
    Width = 1201
    Height = 25
    Align = alBottom
    Caption = 'Load PCAP'
    TabOrder = 0
    OnClick = Button1Click
  end
  object GridPcap: TcxGrid
    Left = 0
    Top = 43
    Width = 1201
    Height = 577
    Align = alClient
    TabOrder = 1
    LockedStateImageOptions.Effect = lsieDark
    LockedStateImageOptions.ShowText = True
    ExplicitTop = 0
    ExplicitHeight = 620
    object GridPcapDBTableView1: TcxGridDBTableView
      Navigator.Buttons.CustomButtons = <>
      FindPanel.DisplayMode = fpdmAlways
      FindPanel.Layout = fplCompact
      FindPanel.Location = fplGroupByBox
      ScrollbarAnnotations.CustomAnnotations = <>
      DataController.DataSource = DsGrid
      DataController.Summary.DefaultGroupSummaryItems = <
        item
          Kind = skCount
          Column = GridPcapDBTableView1NPACKET
        end>
      DataController.Summary.FooterSummaryItems = <
        item
          Kind = skSum
          Column = GridPcapDBTableView1PACKET_LEN
        end>
      DataController.Summary.SummaryGroups = <>
      OptionsBehavior.CellHints = True
      OptionsCustomize.ColumnsQuickCustomization = True
      OptionsCustomize.ColumnsQuickCustomizationSorted = True
      OptionsData.CancelOnExit = False
      OptionsData.Deleting = False
      OptionsData.DeletingConfirmation = False
      OptionsData.Editing = False
      OptionsData.Inserting = False
      OptionsView.CellEndEllipsis = True
      OptionsView.DataRowHeight = 20
      OptionsView.Footer = True
      OptionsView.GridLines = glHorizontal
      OptionsView.HeaderEndEllipsis = True
      OptionsView.Indicator = True
      OptionsView.ShowColumnFilterButtons = sfbAlways
      object GridPcapDBTableView1NPACKET: TcxGridDBColumn
        Caption = 'Count'
        DataBinding.FieldName = 'NPACKET'
        Width = 82
      end
      object GridPcapDBTableView1PACKET_DATE: TcxGridDBColumn
        Caption = 'Date'
        DataBinding.FieldName = 'PACKET_DATE'
        Width = 120
      end
      object GridPcapDBTableView1IP_SRC: TcxGridDBColumn
        Caption = 'Source'
        DataBinding.FieldName = 'IP_SRC'
        Width = 150
      end
      object GridPcapDBTableView1PORT_SRC: TcxGridDBColumn
        Caption = 'Port src'
        DataBinding.FieldName = 'PORT_SRC'
      end
      object GridPcapDBTableView1IP_DST: TcxGridDBColumn
        Caption = 'Dest'
        DataBinding.FieldName = 'IP_DST'
        Width = 150
      end
      object GridPcapDBTableView1PORT_DST: TcxGridDBColumn
        Caption = 'Port dst'
        DataBinding.FieldName = 'PORT_DST'
      end
      object GridPcapDBTableView1PROTOCOL: TcxGridDBColumn
        Caption = 'Protocol'
        DataBinding.FieldName = 'PROTOCOL'
      end
      object GridPcapDBTableView1PACKET_LEN: TcxGridDBColumn
        Caption = 'Len'
        DataBinding.FieldName = 'PACKET_LEN'
        Width = 73
      end
      object GridPcapDBTableView1ETH_TYPE: TcxGridDBColumn
        DataBinding.FieldName = 'ETH_TYPE'
        Visible = False
        Width = 109
      end
      object GridPcapDBTableView1ETH_ACRONYM: TcxGridDBColumn
        Caption = 'Eth type'
        DataBinding.FieldName = 'ETH_ACRONYM'
      end
      object GridPcapDBTableView1MAC_SRC: TcxGridDBColumn
        Caption = 'Mac src'
        DataBinding.FieldName = 'MAC_SRC'
        Width = 150
      end
      object GridPcapDBTableView1MAC_DST: TcxGridDBColumn
        Caption = 'Mac dst'
        DataBinding.FieldName = 'MAC_DST'
        Width = 150
      end
      object GridPcapDBTableView1IPPROTO: TcxGridDBColumn
        DataBinding.FieldName = 'IPPROTO'
        Visible = False
      end
    end
    object GridPcapLevel1: TcxGridLevel
      GridView = GridPcapDBTableView1
    end
  end
  object cxProgressBar1: TcxProgressBar
    Left = 0
    Top = 620
    Align = alBottom
    TabOrder = 2
    Width = 1201
  end
  object EFilter: TcxTextEdit
    AlignWithMargins = True
    Left = 3
    Top = 19
    Align = alTop
    ParentShowHint = False
    Properties.ValidationOptions = [evoShowErrorIcon, evoAllowLoseFocus]
    Properties.OnValidate = EFilterPropertiesValidate
    ShowHint = True
    TabOrder = 3
    ExplicitLeft = -2
    ExplicitTop = 43
    Width = 1195
  end
  object OpenDialog1: TOpenDialog
    Left = 272
    Top = 80
  end
  object FDConnection1: TFDConnection
    Params.Strings = (
      'DriverID=sQLite')
    Left = 872
    Top = 440
  end
  object FDGrid: TFDQuery
    Connection = FDConnection1
    SQL.Strings = (
      'SELECT * FROM PACKETS ORDER BY NPACKET ')
    Left = 944
    Top = 424
    object FDGridNPACKET: TFDAutoIncField
      FieldName = 'NPACKET'
      Origin = 'NPACKET'
      ProviderFlags = [pfInWhere, pfInKey]
      ReadOnly = True
    end
    object FDGridPACKET_LEN: TIntegerField
      FieldName = 'PACKET_LEN'
      Origin = 'PACKET_LEN'
    end
    object FDGridPACKET_DATE: TWideMemoField
      FieldName = 'PACKET_DATE'
      Origin = 'PACKET_DATE'
      BlobType = ftWideMemo
    end
    object FDGridETH_TYPE: TIntegerField
      FieldName = 'ETH_TYPE'
      Origin = 'ETH_TYPE'
    end
    object FDGridETH_ACRONYM: TWideMemoField
      FieldName = 'ETH_ACRONYM'
      Origin = 'ETH_ACRONYM'
      BlobType = ftWideMemo
    end
    object FDGridMAC_SRC: TWideMemoField
      FieldName = 'MAC_SRC'
      Origin = 'MAC_SRC'
      BlobType = ftWideMemo
    end
    object FDGridMAC_DST: TWideMemoField
      FieldName = 'MAC_DST'
      Origin = 'MAC_DST'
      BlobType = ftWideMemo
    end
    object FDGridIPPROTO: TIntegerField
      FieldName = 'IPPROTO'
      Origin = 'IPPROTO'
    end
    object FDGridPROTOCOL: TWideMemoField
      FieldName = 'PROTOCOL'
      Origin = 'PROTOCOL'
      BlobType = ftWideMemo
    end
    object FDGridIP_SRC: TWideMemoField
      FieldName = 'IP_SRC'
      Origin = 'IP_SRC'
      BlobType = ftWideMemo
    end
    object FDGridIP_DST: TWideMemoField
      FieldName = 'IP_DST'
      Origin = 'IP_DST'
      BlobType = ftWideMemo
    end
    object FDGridPORT_SRC: TIntegerField
      FieldName = 'PORT_SRC'
      Origin = 'PORT_SRC'
    end
    object FDGridPORT_DST: TLargeintField
      FieldName = 'PORT_DST'
      Origin = 'PORT_DST'
    end
    object FDGridPACKET_DATA: TBlobField
      FieldName = 'PACKET_DATA'
      Origin = 'PACKET_DATA'
    end
  end
  object FDPhysSQLiteDriverLink1: TFDPhysSQLiteDriverLink
    Left = 888
    Top = 384
  end
  object DsGrid: TDataSource
    DataSet = FDGrid
    Left = 1056
    Top = 488
  end
  object FDScript1: TFDScript
    SQLScripts = <>
    Connection = FDConnection1
    Params = <>
    Macros = <>
    Left = 984
    Top = 368
  end
end
