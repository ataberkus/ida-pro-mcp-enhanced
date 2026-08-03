param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $IdaArgument
)

$idaExe = 'C:\Program Files\IDA Professional 9.4\ida.exe'
if (-not (Test-Path -LiteralPath $idaExe)) {
    throw "IDA executable not found: $idaExe"
}

# IDA 9.4 embeds the Python 3.13 runtime selected by idapyswitch.  Do not let
# a parent Python 3.11 virtual environment override that embedded runtime.
foreach ($name in @(
        'VIRTUAL_ENV',
        'PYTHONHOME',
        'PYTHONPATH',
        'CONDA_PREFIX',
        'CONDA_DEFAULT_ENV',
        'UV_PROJECT_ENVIRONMENT'
    )) {
    Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
}
$env:PYTHONNOUSERSITE = '1'

Start-Process -FilePath $idaExe -ArgumentList $IdaArgument -WorkingDirectory (Split-Path -Parent $idaExe)
