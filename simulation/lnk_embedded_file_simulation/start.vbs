set obj = GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")
set itemObj = obj.Item()
curWorkingDir = Left(WScript.ScriptFullName, InstrRev(WScript.ScriptFullName, "\") - 1)
itemObj.Document.Application.ShellExecute curWorkingDir & "\" & "simi.bat", Null, curWorkingDir, Null, 0
set obj = Nothing