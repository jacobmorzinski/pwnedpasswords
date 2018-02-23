# https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/
# https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/

# Get a password from the user.
# SHA1 hash it.
# Send some prefix of the hash to https://api.pwnedpasswords.com/range/$prefix
# Get results of web call.
# For each result, check to see if it matches the full hash.
# If a match is found, print a message and a count.
# If no match is found, print a message.

function Get-UserPassword {
    $SecurePassword = Read-Host -AsSecureString -Prompt "Password"
    $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecurePassword)
    $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    return $UnsecurePassword
}

# Test data is in the files test.txt, testLF.txt, testCRLF.txt
function Get-StringHash ([string] $String, $HashName = "SHA1") {
    $StringBuilder = New-Object System.Text.StringBuilder
    $hasher = [System.Security.Cryptography.HashAlgorithm]::Create($HashName)
    $StringBytes = [System.Text.Encoding]::UTF8.GetBytes($String)
    $hash = $hasher.ComputeHash($StringBytes)
    $hash | ForEach-Object { [void] $StringBuilder.Append( $_.ToString("x2")) }
    return $StringBuilder.ToString().ToUpper()
}

function Invoke-PwnedPasswords ([string] $prefix) {
    try {
        $response = Invoke-WebRequest "https://api.pwnedpasswords.com/range/${prefix}"
    }
    catch [Net.WebException] {
        # Write-Host $_.Exception.GetType().FullName
        # https://stackoverflow.com/questions/41618766/powershell-invoke-webrequest-fails-with-ssl-tls-secure-channel
        if ( $_.Exception.Status -eq [Net.WebExceptionStatus]::SecureChannelFailure ) {
            [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $response = Invoke-WebRequest "https://api.pwnedpasswords.com/range/${prefix}"
        }
    }

    $matches = $response.Content -split [Environment]::NewLine
    return $matches
}

$password = Get-UserPassword
$password_sha1 = Get-StringHash $password
$password_sha1_prefix = $password_sha1.Substring(0,5)
$matches = Invoke-PwnedPasswords $password_sha1_prefix

foreach ($match in $matches) {
    $recombined = $password_sha1_prefix + $match
    ($hash, $number) = $recombined.Split(":", 2)
    if ($hash -imatch $password_sha1) {
        Write-Verbose $recombined
        return "MATCH (occurs $number times in breaches)"
    }
}
return "No match (in the known breaches)"
