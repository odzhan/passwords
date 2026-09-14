param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [int]$Seconds = 5,
    [int]$Repetitions = 3,
    [int[]]$Threads = @(1,12)
)
$ErrorActionPreference = 'Stop'
if ($Seconds -lt 3 -or $Repetitions -lt 1 -or $Repetitions%2 -eq 0) { throw 'Use at least 3 seconds and an odd positive repetition count.' }
if (@($Threads | Where-Object { $_ -lt 1 }).Count) { throw 'Thread counts must be positive.' }
$exe = (Resolve-Path -LiteralPath $Executable).Path
# Each process searches a large seven-character range. Read its last cumulative
# progress rate before terminating only that benchmark process. No user hashes.
foreach ($version in @('1','2','3','4','5','6','7','8','9','11','5x')) {
  foreach ($threadCount in $Threads) {
    $rates = @()
    for ($repeat=0; $repeat -lt $Repetitions; $repeat++) {
        $start = if ($version -in @('9','11')) { '0000000' } else { 'AAAAAAA' }
        $info = [System.Diagnostics.ProcessStartInfo]::new()
        $info.FileName = $exe
        $info.Arguments = "0000000000000000 -v$version -s $start -e ZZZZZZZ -t $threadCount"
        $info.UseShellExecute = $false
        $info.CreateNoWindow = $true
        $info.RedirectStandardOutput = $true
        $info.RedirectStandardError = $true
        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $info
        try {
            [void]$process.Start()
            $output = $process.StandardOutput.ReadToEndAsync()
            $errors = $process.StandardError.ReadToEndAsync()
            if ($process.WaitForExit($Seconds * 1000 + 250)) {
                throw "v${version} ended early: exit=$($process.ExitCode) $($errors.Result)"
            }
            $process.Kill()
            $process.WaitForExit()
            if ($output.Result -notmatch "thread cnt\s+: $threadCount\b") { throw 'Actual thread count differs from requested count.' }
            $matches = [regex]::Matches($output.Result, '([0-9.]+)M k/s')
            if ($matches.Count -eq 0) { throw "v${version}: no progress samples. $($errors.Result)" }
            $rates += [double]::Parse($matches[$matches.Count-1].Groups[1].Value,
                [System.Globalization.CultureInfo]::InvariantCulture)
        } finally {
            if ($process.Id -and !$process.HasExited) { $process.Kill(); $process.WaitForExit() }
            $process.Dispose()
        }
    }
    $sorted = @($rates | Sort-Object)
    [pscustomobject]@{
        Version = $version
        Threads = $threadCount
        MedianMps = $sorted[[int][math]::Floor($sorted.Count/2)]
        MinMps = $sorted[0]
        MaxMps = $sorted[-1]
        Samples = ($rates -join ', ')
    }
  }
}
