object Form2: TForm2
  Left = 0
  Top = 0
  Caption = 'PCAP Analisys'
  ClientHeight = 612
  ClientWidth = 1136
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object Button1: TButton
    Left = 0
    Top = 587
    Width = 1136
    Height = 25
    Align = alBottom
    Caption = 'Load PCAP'
    TabOrder = 0
    OnClick = Button1Click
    ExplicitWidth = 945
  end
  object GridPcap: TcxGrid
    Left = 0
    Top = 0
    Width = 1136
    Height = 566
    Align = alClient
    TabOrder = 1
    LockedStateImageOptions.Effect = lsieDark
    LockedStateImageOptions.ShowText = True
    ExplicitWidth = 945
    object GridPcapTableView1: TcxGridTableView
      Navigator.Buttons.CustomButtons = <>
      FindPanel.DisplayMode = fpdmAlways
      FindPanel.Layout = fplCompact
      FindPanel.Location = fplGroupByBox
      ScrollbarAnnotations.CustomAnnotations = <>
      DataController.Summary.DefaultGroupSummaryItems = <
        item
          Kind = skCount
          Column = GridPcapTableView1COUNT
        end>
      DataController.Summary.FooterSummaryItems = <
        item
          Kind = skSum
          OnGetText = GridPcapTableView1TcxGridDataControllerTcxDataSummaryFooterSummaryItems0GetText
          Column = GridPcapTableView1LEN
        end>
      DataController.Summary.SummaryGroups = <>
      OptionsBehavior.CellHints = True
      OptionsBehavior.ShowLockedStateImageOptions.BestFit = lsimImmediate
      OptionsBehavior.ShowLockedStateImageOptions.Filtering = lsimImmediate
      OptionsBehavior.ShowLockedStateImageOptions.Grouping = lsimImmediate
      OptionsBehavior.ShowLockedStateImageOptions.Sorting = lsimImmediate
      OptionsBehavior.ShowLockedStateImageOptions.Posting = lsimImmediate
      OptionsCustomize.ColumnsQuickCustomization = True
      OptionsCustomize.ColumnsQuickCustomizationReordering = qcrEnabled
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
      object GridPcapTableView1COUNT: TcxGridColumn
        Caption = 'Count'
        DataBinding.ValueType = 'Integer'
        SortIndex = 0
        SortOrder = soAscending
        Width = 59
      end
      object GridPcapTableView1DATA: TcxGridColumn
        Caption = 'Date time'
        DataBinding.ValueType = 'DateTime'
        Width = 136
      end
      object GridPcapTableView1SRC: TcxGridColumn
        Caption = 'Src'
        Width = 146
      end
      object GridPcapTableView1PORTSRC: TcxGridColumn
        Caption = 'Port src'
      end
      object GridPcapTableView1DST: TcxGridColumn
        Caption = 'Dest'
        Width = 136
      end
      object GridPcapTableView1PORTDST: TcxGridColumn
        Caption = 'Port dst'
      end
      object GridPcapTableView1PROTO: TcxGridColumn
        Caption = 'Proto'
        Width = 74
      end
      object GridPcapTableView1IPPROTO: TcxGridColumn
        Caption = 'IP PROTO'
        Visible = False
      end
      object GridPcapTableView1LEN: TcxGridColumn
        Caption = 'Len'
        DataBinding.ValueType = 'Integer'
        Width = 78
      end
      object GridPcapTableView1ETHTYPE: TcxGridColumn
        Caption = 'Eth type'
      end
      object GridPcapTableView1ETHTYPENUM: TcxGridColumn
        Caption = 'ETH TYPE NUM'
        Visible = False
      end
      object GridPcapTableView1MACSrc: TcxGridColumn
        Caption = 'Mac src'
        Width = 136
      end
      object GridPcapTableView1MacDst: TcxGridColumn
        Caption = 'Mac dst'
        Width = 136
      end
    end
    object GridPcapLevel1: TcxGridLevel
      GridView = GridPcapTableView1
    end
  end
  object cxProgressBar1: TcxProgressBar
    Left = 0
    Top = 566
    Align = alBottom
    TabOrder = 2
    ExplicitWidth = 945
    Width = 1136
  end
  object OpenDialog1: TOpenDialog
    Left = 272
    Top = 80
  end
end
