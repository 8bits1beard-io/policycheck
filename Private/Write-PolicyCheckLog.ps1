function Write-PolicyCheckLog {
    <#
    .SYNOPSIS
        Writes operational log entries for PolicyCheck.
    .DESCRIPTION
        Appends timestamped log entries to the PolicyCheck log file.
        Used for operational tracking of script execution, not device data.
    .PARAMETER Message
        The log message to write.
    .PARAMETER Level
        Log level: Info, Warning, or Error. Defaults to Info.
    .PARAMETER LogPath
        Path to the log file. If not specified, uses the script-scoped $Script:LogPath.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,

        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info',

        [string]$LogPath
    )

    # Use provided path or fall back to script-scoped variable
    $targetPath = if ($LogPath) { $LogPath } elseif ($Script:LogPath) { $Script:LogPath } else { return }

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $levelPadded = "[$($Level.ToUpper())]".PadRight(9)
    $logEntry = "$timestamp $levelPadded $Message"

    try {
        # Ensure directory exists
        $logDir = Split-Path $targetPath -Parent
        if ($logDir -and -not (Test-Path $logDir)) {
            New-Item -Path $logDir -ItemType Directory -Force | Out-Null
        }

        # Append to log file
        $logEntry | Out-File -FilePath $targetPath -Append -Encoding UTF8
    }
    catch {
        # Silent fail - don't break the script for logging issues
        Write-Verbose "Failed to write log: $_"
    }
}
