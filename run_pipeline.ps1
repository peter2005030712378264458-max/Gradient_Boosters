param(
    [Parameter(Mandatory = $true)]
    [string]$InputDir,
    [string]$RunDir,
    [string]$IncludeList,
    [int]$Workers = 4,
    [int]$PdfWorkers = 2,
    [int]$FileTimeout = 600,
    [double]$MaxFileSizeMb = 100,
    [int]$MaxRows = 50000,
    [switch]$NoOcr
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Arguments = @(
    "$ScriptDir\run_pipeline.py",
    "--input-dir", $InputDir,
    "--workers", $Workers,
    "--pdf-workers", $PdfWorkers,
    "--file-timeout", $FileTimeout,
    "--max-file-size-mb", $MaxFileSizeMb,
    "--max-rows", $MaxRows
)

if ($RunDir) {
    $Arguments += @("--run-dir", $RunDir)
}
if ($IncludeList) {
    $Arguments += @("--include-list", $IncludeList)
}
if ($NoOcr) {
    $Arguments += "--no-ocr"
}

python -X utf8 @Arguments
exit $LASTEXITCODE
