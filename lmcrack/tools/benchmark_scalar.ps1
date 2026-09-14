param(
    [Parameter(Mandatory=$true)][string]$BuildDirectory,
    [int]$Seconds=5,
    [int]$Repetitions=3,
    [int[]]$Threads=@(1,12)
)
# Shared process control and rotating-order measurement logic.
& "$PSScriptRoot/benchmark_v7_comparison.ps1" -BuildDirectory $BuildDirectory `
    -Seconds $Seconds -Repetitions $Repetitions -Threads $Threads `
    -Versions @(4,5,6) -Alphabets @('ABCDEFGHIJKLMNOPQRSTUVWXYZ') `
    -Variants @('lmcrack_scalar_default','lmcrack_scalar_pair64','lmcrack_scalar_pair256')
