param(
    [Parameter(Mandatory=$true)][string]$BuildDirectory,
    [int]$Seconds=5,
    [int]$Repetitions=3,
    [int[]]$Threads=@(1,12),
    [string[]]$Versions=@('7'),
    [string[]]$Variants=@('lmcrack_reference_transpose','lmcrack_reference_lane','lmcrack'),
    [string[]]$Alphabets=@('ABCDEFGHIJKLMNOPQRSTUVWXYZ','0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        '!#%0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_')
)
$ErrorActionPreference='Stop'
if($Seconds -lt 3 -or $Repetitions -lt 3 -or ($Repetitions % 2) -eq 0) {
    throw 'Use at least 3 seconds and an odd repetition count of at least 3.'
}
if(@($Threads | Where-Object { $_ -lt 1 }).Count) { throw 'Thread counts must be positive.' }
$directory=(Resolve-Path -LiteralPath $BuildDirectory).Path
if($Variants.Count -eq 0 -or @($Versions | Where-Object { $_ -notmatch '^([1-9]|11|5x)$' }).Count) {
    throw 'Provide executable variants and supported versions.'
}
foreach($alphabet in $Alphabets) {
    if($alphabet -notmatch '^[!#%0-9A-Z_]{2,128}$') { throw 'Alphabet must use the supported shell-safe symbols.' }
}
foreach($variant in $variants) {
    $parts=$variant.Split(':')
    if($parts.Count -gt 2 -or ($parts.Count -eq 2 -and $parts[1] -notmatch '^([1-9]|11|5x)$')) {
        throw 'Variant must be executable-name or executable-name:version.'
    }
    if(!(Test-Path -LiteralPath (Join-Path $directory "$($parts[0]).exe"))) { throw "Missing $variant executable" }
}
foreach($alphabet in $alphabets) {
  foreach($version in $Versions) {
    foreach($threadCount in $Threads) {
        $rates=@{}; foreach($variant in $variants) { $rates[$variant]=@() }
        for($repeat=0;$repeat -lt $Repetitions;$repeat++) {
            # Rotate execution order so every variant occupies each position.
            for($offset=0;$offset -lt $variants.Count;$offset++) {
                $variant=$variants[($repeat+$offset)%$variants.Count]
                $info=[System.Diagnostics.ProcessStartInfo]::new()
                $parts=$variant.Split(':')
                $selectedVersion=if($parts.Count -eq 2){$parts[1]}else{$version}
                $info.FileName=Join-Path $directory "$($parts[0]).exe"
                $start=([string]$alphabet[0])*7
                $end=([string]$alphabet[$alphabet.Length-1])*7
                $info.Arguments="0000000000000000 -v$selectedVersion -c $alphabet -s $start -e $end -t $threadCount"
                $info.UseShellExecute=$false
                $info.CreateNoWindow=$true
                $info.RedirectStandardOutput=$true
                $info.RedirectStandardError=$true
                $process=[System.Diagnostics.Process]::new()
                $process.StartInfo=$info
                $started=$false
                try {
                    $started=$process.Start()
                    $stdout=$process.StandardOutput.ReadToEndAsync()
                    $stderr=$process.StandardError.ReadToEndAsync()
                    if($process.WaitForExit($Seconds*1000+250)) {
                        throw "Benchmark ended early: $variant exit=$($process.ExitCode) $($stderr.Result)"
                    }
                    $process.Kill(); $process.WaitForExit()
                    $text=$stdout.Result
                    if($text -notmatch "thread cnt\s+: $threadCount\b") {
                        throw 'Actual thread count differs from requested count.'
                    }
                    $samples=[regex]::Matches($text,'([0-9.]+)M k/s')
                    if($samples.Count -lt 2) { throw "Insufficient samples: $variant" }
                    $rates[$variant]+=[double]::Parse($samples[$samples.Count-1].Groups[1].Value,
                        [System.Globalization.CultureInfo]::InvariantCulture)
                } finally {
                    if($started -and !$process.HasExited) { $process.Kill(); $process.WaitForExit() }
                    $process.Dispose()
                }
            }
        }
        foreach($variant in $variants) {
            $sorted=@($rates[$variant] | Sort-Object)
            $parts=$variant.Split(':')
            $selectedVersion=if($parts.Count -eq 2){$parts[1]}else{$version}
            [pscustomobject]@{
                Alphabet=$alphabet; Version=$selectedVersion; Threads=$threadCount; Variant=$variant
                MedianMps=$sorted[[int][math]::Floor($Repetitions/2)]
                MinMps=$sorted[0]; MaxMps=$sorted[-1]; Samples=($rates[$variant] -join ',')
            }
        }
    }
  }
}
