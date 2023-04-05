object FormLabelFilter: TFormLabelFilter
  Left = 0
  Top = 0
  BorderStyle = bsDialog
  Caption = 'Filter by label'
  ClientHeight = 629
  ClientWidth = 777
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  OldCreateOrder = False
  Position = poMainFormCenter
  PixelsPerInch = 96
  TextHeight = 13
  object cxDBTreeList1: TcxDBTreeList
    Left = 0
    Top = 0
    Width = 777
    Height = 629
    Align = alClient
    Bands = <
      item
      end>
    DataController.DataSource = DsList
    DataController.ParentField = 'ID_LABEL_NAME'
    DataController.KeyField = 'ID_LABEL_NAME'
    FindPanel.DisplayMode = fpdmAlways
    FindPanel.Layout = fplCompact
    Navigator.Buttons.CustomButtons = <>
    OptionsData.CancelOnExit = False
    OptionsData.Editing = False
    OptionsData.Deleting = False
    OptionsData.CheckHasChildren = False
    OptionsView.CellAutoHeight = True
    OptionsView.CellEndEllipsis = True
    OptionsView.ColumnAutoWidth = True
    RootValue = -1
    ScrollbarAnnotations.CustomAnnotations = <>
    TabOrder = 0
    OnDblClick = cxDBTreeList1DblClick
    ExplicitTop = -40
    object cxDBTreeList1cxDBTreeListColumn1: TcxDBTreeListColumn
      Caption.Text = 'Label name'
      DataBinding.FieldName = 'LABEL_NAME'
      Width = 304
      Position.ColIndex = 0
      Position.RowIndex = 0
      Position.BandIndex = 0
      SortOrder = soAscending
      SortIndex = 0
      Summary.FooterSummaryItems = <>
      Summary.GroupFooterSummaryItems = <>
    end
    object cxDBTreeList1cxDBTreeListColumn2: TcxDBTreeListColumn
      Caption.Text = 'Description'
      DataBinding.FieldName = 'DESCRIPTION'
      Width = 454
      Position.ColIndex = 1
      Position.RowIndex = 0
      Position.BandIndex = 0
      Summary.FooterSummaryItems = <>
      Summary.GroupFooterSummaryItems = <>
    end
  end
  object DsList: TDataSource
    Left = 392
    Top = 368
  end
end
