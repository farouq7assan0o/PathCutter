param([Parameter(Mandatory)][string]$Path)
# Prints every command invocation the REAL PowerShell parser finds: [{name, start, end}]. Used by tests/test_ps_ast.py.
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
$found = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -or $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true) | ForEach-Object {
    $name = if ($_ -is [System.Management.Automation.Language.CommandAst]) { $_.GetCommandName() } else { '.' + $_.Member.Extent.Text }
    [pscustomobject]@{ name = $name; start = $_.Extent.StartLineNumber; end = $_.Extent.EndLineNumber }
}
[pscustomobject]@{ errors = @($errors).Count; commands = @($found) } | ConvertTo-Json -Depth 4 -Compress
