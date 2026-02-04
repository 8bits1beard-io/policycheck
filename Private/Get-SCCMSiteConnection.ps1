function Get-SCCMSiteConnection {
    <#
    .SYNOPSIS
        Auto-discovers and connects to the SCCM SMS Provider.
    .DESCRIPTION
        Discovers the SCCM site server and site code from the local client registry,
        then establishes a connection to the SMS Provider WMI namespace for querying
        deployment information.
    .PARAMETER SiteServer
        Optional override for the SMS Provider server. If not specified, auto-discovered
        from client registry.
    .PARAMETER SiteCode
        Optional override for the SCCM site code. If not specified, auto-discovered
        from client WMI.
    .PARAMETER Credential
        PSCredential for authenticating to the site server. Required for cross-domain
        or non-domain scenarios.
    .OUTPUTS
        PSCustomObject with connection info (Server, SiteCode, Namespace, Connected, Message)
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [string]$SiteServer,
        [string]$SiteCode,
        [PSCredential]$Credential
    )

    Write-Verbose "Establishing SCCM site connection..."

    $result = [PSCustomObject]@{
        Connected  = $false
        Server     = $null
        SiteCode   = $null
        Namespace  = $null
        Message    = $null
    }

    # --- Auto-discover Site Code from client WMI if not provided ---
    if (-not $SiteCode) {
        Write-Verbose "Auto-discovering site code from client WMI..."
        try {
            $siteAuthority = Get-CimInstance -Namespace 'root\ccm' -ClassName SMS_Authority -ErrorAction Stop | Select-Object -First 1
            if ($siteAuthority -and $siteAuthority.Name) {
                # SMS_Authority.Name is in format "SMS:<SiteCode>"
                $SiteCode = $siteAuthority.Name -replace '^SMS:', ''
                Write-Verbose "Discovered site code: $SiteCode"
            }
        }
        catch {
            Write-Verbose "Could not discover site code from WMI: $_"
        }
    }

    if (-not $SiteCode) {
        $result.Message = "Could not determine SCCM site code. Specify -SCCMSiteCode parameter."
        return $result
    }

    # --- Auto-discover Site Server from client registry if not provided ---
    if (-not $SiteServer) {
        Write-Verbose "Auto-discovering site server from client registry..."

        # Try LocalMP from Mobile Client registry
        try {
            $mobileClientKey = 'HKLM:\SOFTWARE\Microsoft\SMS\Mobile Client'
            if (Test-Path $mobileClientKey) {
                $localMP = (Get-ItemProperty -Path $mobileClientKey -Name 'Local Management Point' -ErrorAction SilentlyContinue).'Local Management Point'
                if ($localMP) {
                    $SiteServer = $localMP
                    Write-Verbose "Discovered site server from LocalMP: $SiteServer"
                }
            }
        }
        catch {
            Write-Verbose "Could not read Local Management Point: $_"
        }

        # Fallback: Try SMS_LookupMP WMI class
        if (-not $SiteServer) {
            try {
                $lookupMP = Get-CimInstance -Namespace 'root\ccm' -ClassName SMS_LookupMP -ErrorAction Stop | Select-Object -First 1
                if ($lookupMP -and $lookupMP.Name) {
                    $SiteServer = $lookupMP.Name
                    Write-Verbose "Discovered site server from SMS_LookupMP: $SiteServer"
                }
            }
            catch {
                Write-Verbose "Could not discover site server from SMS_LookupMP: $_"
            }
        }

        # Fallback: Try CurrentManagementPoint from CCM_Authority
        if (-not $SiteServer) {
            try {
                $ccmAuthority = Get-CimInstance -Namespace 'root\ccm' -ClassName CCM_Authority -ErrorAction Stop | Select-Object -First 1
                if ($ccmAuthority -and $ccmAuthority.CurrentManagementPoint) {
                    $SiteServer = $ccmAuthority.CurrentManagementPoint
                    Write-Verbose "Discovered site server from CCM_Authority: $SiteServer"
                }
            }
            catch {
                Write-Verbose "Could not discover site server from CCM_Authority: $_"
            }
        }
    }

    if (-not $SiteServer) {
        $result.Message = "Could not determine SCCM site server. Specify -SCCMSiteServer parameter."
        return $result
    }

    # --- Build the SMS Provider namespace ---
    $smsNamespace = "root\SMS\site_$SiteCode"
    Write-Verbose "Connecting to SMS Provider: $SiteServer - $smsNamespace"

    # --- Test connection to SMS Provider ---
    try {
        $cimParams = @{
            ComputerName = $SiteServer
            Namespace    = $smsNamespace
            ClassName    = 'SMS_Site'
            ErrorAction  = 'Stop'
        }

        if ($Credential) {
            # For remote connections with credentials, we need CimSession
            $sessionParams = @{
                ComputerName = $SiteServer
                Credential   = $Credential
                ErrorAction  = 'Stop'
            }

            # Try DCOM first (more common for SCCM), then WinRM
            try {
                $sessionOption = New-CimSessionOption -Protocol Dcom
                $cimSession = New-CimSession @sessionParams -SessionOption $sessionOption
            }
            catch {
                Write-Verbose "DCOM connection failed, trying WinRM: $_"
                $cimSession = New-CimSession @sessionParams
            }

            $siteInfo = Get-CimInstance -CimSession $cimSession -Namespace $smsNamespace -ClassName SMS_Site -ErrorAction Stop | Select-Object -First 1
            Remove-CimSession $cimSession -ErrorAction SilentlyContinue
        }
        else {
            # Try direct connection without credentials
            $siteInfo = Get-CimInstance @cimParams | Select-Object -First 1
        }

        if ($siteInfo) {
            $result.Connected = $true
            $result.Server = $SiteServer
            $result.SiteCode = $SiteCode
            $result.Namespace = $smsNamespace
            Write-Verbose "Successfully connected to SMS Provider. Site: $($siteInfo.SiteName)"
        }
        else {
            $result.Message = "Connected to $SiteServer but SMS_Site query returned no data."
        }
    }
    catch {
        $result.Message = "Could not connect to SMS Provider on $SiteServer`: $_"
        Write-Verbose "SMS Provider connection failed: $_"
    }

    return $result
}
