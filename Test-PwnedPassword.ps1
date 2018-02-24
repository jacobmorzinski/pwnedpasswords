<#
.SYNOPSIS
    Test if password is included in Have I Been Pwned's "Pwned Passwords".

.DESCRIPTION
    Query haveibeenpwned.com to see if a password has previously been exposed in data breaches.  If the password is exposed in breaches, also report a count of how many times the password has been seen.

    If you pass no parameters, you are prompted for the password to check and the password is not echoed to the screen.

    To protect the source password, the Pwned Passwords search is performed by partial hash: only the first 5 characters of a SHA-1 password hash are sent to haveibeenpwned.com.  The server only learns the 5-character prefix, and never learns the full SHA-1 hash of the password being tested.  Only the client (this script) knows the password being tested.

.PARAMETER password_notsecure

    Pass a plaintext password. This option is for convenience, but not recommended.
    If used with real passwords, clear your history and transcripts after use.

.PARAMETER password_secure

    Pass a SecureString password, for example from a file.

.EXAMPLE
    PS C:\> .\Test-PwnedPassword.ps1
    Password: *******

    Pwned  Seen Hash
    -----  ---- ----
     True 16092 F3BBBD66A63D4BF1747940578EC3D0103530E21D

.EXAMPLE
    PS C:\> @("123", "test") | .\Test-PwnedPassword.ps1

    Pwned   Seen Hash
    -----   ---- ----
     True 977827 40BD001563085FC35165329EA1FF5C5ECBDBBEEF
     True  68340 A94A8FE5CCB19BA61C4C0873D391E987982FBBD3

.EXAMPLE
    PS C:\> $ss = Read-Host -AsSecureString
    ****
    PS C:\> .\Test-PwnedPassword.ps1 -password_secure $ss

    Pwned  Seen Hash
    -----  ---- ----
     True 68340 A94A8FE5CCB19BA61C4C0873D391E987982FBBD3

.INPUTS
    Passwords from parameters, pipeline, or interactive prompt.

.OUTPUTS
    Object with proprties "Pwned", "Seen", "Hash" for each input password.

.NOTES
    Takes inspiration from https://gist.github.com/lzybkr / Get-AmIPwned.ps1

.LINK
    https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/
    https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/
    https://haveibeenpwned.com/API/v2#PwnedPasswords
#>


[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline)]
    [string]
    $password_notsecure,

    [Parameter(ValueFromPipeline)]
    [SecureString]
    $password_secure
)

# Get password(s).
# For each password:
# SHA1 hash it.
# Send 5-character prefix of the hash to https://api.pwnedpasswords.com/range/$prefix
# Get results of web call.
# Check to see one of the results matches the original hash.

begin
{
    class PwnedPasswordResult {
        [bool]$Pwned
        [int]$Seen
        [string]$Hash
    }

    $ProgressPreference = 'Ignore'

    # https://stackoverflow.com/questions/41618766/powershell-invoke-webrequest-fails-with-ssl-tls-secure-channel
    $originalSecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    if ($originalSecurityProtocol.HasFlag([System.Net.SecurityProtocolType]::Tls)) {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bOR [System.Net.SecurityProtocolType]::Tls12
    }

    # Pull the cleartext out of a SecureString 
    function ConvertTo-String ([securestring] $secure_string) {
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure_string)
        $insecure_string = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        return $insecure_string
    }

    # PS> Get-StringHash "test"
    # A94A8FE5CCB19BA61C4C0873D391E987982FBBD3
    function Get-StringHash ([string] $String, $Algorithm = "SHA1") {
        $StringBuilder = New-Object System.Text.StringBuilder
        $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($Algorithm)
        $StringBytes = [System.Text.Encoding]::ASCII.GetBytes($String)
        $hash = $hasher.ComputeHash($StringBytes)
        $hash | ForEach-Object { [void] $StringBuilder.Append( $_.ToString("x2")) }
        return $StringBuilder.ToString().ToUpper()
    }
    
    # Input: a 5-character hash prefix
    # Ouptut: an array of objects with "count" and "suffix" properties
    function Invoke-PwnedPasswords ([string] $prefix) {
        $response = Invoke-WebRequest "https://api.pwnedpasswords.com/range/${prefix}"
        $api_suffixes = $response.Content -split [Environment]::NewLine
        foreach ($suffix in $api_suffixes) {
            if ($suffix -imatch "([a-f0-9]+):(\d+)") {
                $props = @{"suffix"=$Matches[1]; "count"=$Matches[2]}
                New-Object -TypeName PSObject -Property $props # -> output pipeline
            }
        }
    }
    
}

process
{

    if (!$password_secure -and !$password_notsecure) {
        $password_secure = Read-Host -AsSecureString -Prompt "Password"
    }

    if (!$password_notsecure) {
        $password_notsecure = ConvertTo-String $password_secure
    }

    $password_sha1 = Get-StringHash -Algorithm "SHA1" $password_notsecure
    $password_notsecure = $null

    $password_sha1_prefix = $password_sha1.Substring(0,5)
    $password_sha1_suffix = $password_sha1.Substring(5)
    $api_suffixes = Invoke-PwnedPasswords $password_sha1_prefix

    $pwned = $false
    $count = 0
    foreach ($entry in $api_suffixes) {
        if ($entry.suffix -ieq $password_sha1_suffix) {
            $pwned = $true
            $count = $entry.count
        }
    }

    [PwnedPasswordResult]@{
        Pwned = $pwned
        Seen = $count
        Hash = $password_sha1
    }

}

end
{
    [System.Net.ServicePointManager]::SecurityProtocol = $originalSecurityProtocol
}