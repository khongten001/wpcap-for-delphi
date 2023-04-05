unit UnFunctionFilter;



interface

uses
  cxGridTableView, cxGridCustomTableView, cxGridCustomView, System.SysUtils,
  cxGridDBTableView, cxFilterControlUtils, cxFilter, System.Variants,
  System.StrUtils;

Function GetCriteriaNodeFilter(aRootFilter:TcxFilterCriteriaItemList;aOperator:TcxFilterBoolOperatorKind):TcxFilterCriteriaItemList;
procedure FilterFlowSelected(aGridView: TcxGridDBTableView);
procedure FilterCellValueSelected(aGridView : TcxGridDBTableView);
function GetCellValueSelected(aGridView : TcxGridDBTableView;var Value, DislayValue: Variant): Boolean;
procedure FilterColumn(aColumn:TcxGridDBColumn;aGridView:TcxGridDBTableView;aOperator:TcxFilterOperatorKind;aValue:Variant;aDislayValue:String='';aClear:Boolean=False);

implementation


procedure FilterFlowSelected(aGridView: TcxGridDBTableView);
var LGroupItems : TcxFilterCriteriaItemList;

    Procedure AddFilter(aColumnName,aColumnValue:String);
    var LColumn       : TcxGridDBColumn;
        LColumnValue  : TcxGridDBColumn;
    begin
      LColumn        := aGridView.GetColumnByFieldName(aColumnName);
      LColumnValue   := aGridView.GetColumnByFieldName(aColumnValue);      
      LGroupItems.AddItem(LColumn, foEqual,aGridView.Controller.FocusedRow.Values[LColumnValue.Index], aGridView.Controller.FocusedRow.Values[LColumnValue.Index]);    
    end;
    
begin
  if Assigned(aGridView.Controller.FocusedRow) then
  begin
    aGridView.DataController.Filter.BeginUpdate;
    Try
      aGridView.DataController.Filter.Root.Clear;
      aGridView.DataController.Filter.Root.BoolOperatorKind := fboOr;
      LGroupItems := aGridView.DataController.Filter.Root.AddItemList(fboAnd);
      AddFilter('IP_SRC','IP_SRC');
      AddFilter('IP_DST','IP_DST');
      AddFilter('PORT_DST','PORT_DST');
      AddFilter('PORT_SRC','PORT_SRC'); 
      LGroupItems  := aGridView.DataController.Filter.Root.AddItemList(fboAnd);
      AddFilter('IP_SRC','IP_DST');
      AddFilter('IP_DST','IP_SRC');
      AddFilter('PORT_DST','PORT_SRC');
      AddFilter('PORT_SRC','PORT_DST'); 
      aGridView.DataController.Filter.Active := True;
    Finally
      aGridView.DataController.Filter.EndUpdate
    End;
  end;
end;

procedure FilterColumn(aColumn:TcxGridDBColumn;aGridView : TcxGridDBTableView;aOperator:TcxFilterOperatorKind;aValue:Variant;aDislayValue:String='';aClear:Boolean=False);
var LGroupItems : TcxFilterCriteriaItemList;
begin
  aGridView.DataController.Filter.BeginUpdate;
  Try
    if aClear then
      aGridView.DataController.Filter.Root.Clear;
    LGroupItems  := GetCriteriaNodeFilter(aGridView.DataController.Filter.Root,fboAnd);

    if ( aOperator = foInList) or ( aOperator = foNotInList) then
      LGroupItems.AddItem(aColumn, aOperator, aValue, aDislayValue )     
    else
      LGroupItems.AddItem(aColumn, aOperator, aValue, ifthen(Trim(aDislayValue) = '',VarToStrDef(aValue,''),aDislayValue) );
    aGridView.DataController.Filter.Active := True;
  Finally
    aGridView.DataController.Filter.EndUpdate
  End;    
end;

procedure FilterCellValueSelected(aGridView : TcxGridDBTableView);
var LValue      : Variant; 
    LDislayValue: Variant;
    LGroupItems : TcxFilterCriteriaItemList;
begin
  if Not aGridView.OptionsSelection.CellSelect then Exit;

  if GetCellValueSelected(aGridView,LValue,LDislayValue) then
  begin
    aGridView.DataController.Filter.BeginUpdate;
    Try
      LGroupItems := GetCriteriaNodeFilter(aGridView.DataController.Filter.Root,fboAnd);
      LGroupItems.AddItem(aGridView.Controller.FocusedColumn, foEqual ,LValue,LDislayValue);
      aGridView.DataController.Filter.Active := True;
    Finally
      aGridView.DataController.Filter.EndUpdate
    End;    
  end;
end;

function GetCellValueSelected(aGridView : TcxGridDBTableView;var Value, DislayValue: Variant): Boolean;
begin
  Result := False;
  with aGridView.Controller do
  begin
    if aGridView.OptionsSelection.CellSelect then
    begin
      if not Assigned(FocusedColumn) then exit;

      if not FocusedColumn.Options.Filtering then Exit;

      if not Assigned(FocusedRow) then Exit;
      
      DislayValue := aGridView.DataController.DisplayTexts[aGridView.DataController.FocusedRecordIndex, FocusedColumn.Index];
      value       := aGridView.DataController.Values[aGridView.DataController.FocusedRecordIndex, FocusedColumn.Index];
      Result      := True;
    end;
  end;
end;


Function GetCriteriaNodeFilter(aRootFilter:TcxFilterCriteriaItemList;aOperator:TcxFilterBoolOperatorKind):TcxFilterCriteriaItemList;
var I : Integer;
begin
  if aRootFilter.Count = 0 then
  begin
    if aRootFilter.BoolOperatorKind = aOperator then
    begin
      Result                  := aRootFilter;
      Result.BoolOperatorKind := aOperator;
    end
    else
      Result := aRootFilter.AddItemList(aOperator)
  end
  else
  begin
    for I := aRootFilter.Count -1 downto 0 do
    begin
      if aRootFilter.Items[I].IsItemList then
      begin
        if TcxFilterCriteriaItemList(aRootFilter.Items[I]).BoolOperatorKind = aOperator  then
        begin
          Result := TcxFilterCriteriaItemList(aRootFilter.Items[I]);
          Exit;
        end
      end;
    end;

    if aRootFilter.BoolOperatorKind = aOperator then
      Result := aRootFilter
    else
      Result := aRootFilter.AddItemList(aOperator)
  end;
end;


end.
