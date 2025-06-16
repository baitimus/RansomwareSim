<#
.SYNOPSIS
    AES Encryption/Decryption Module for Ransomware Awareness Simulation
.DESCRIPTION
    This module provides AES-256 encryption and decryption functions for
    the Ransomware Awareness Simulation tool. It allows encrypting files
    for educational demonstration purposes only.
.NOTES
    Author: Security Education Team
    Version: 2.0
    Purpose: Educational demonstration only
#>

#region Helper Functions
function Write-AesLog {
    param(
        [Parameter(Mandatory)]
        [string]$Message,
        
        [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug')]
        [string]$Level = 'Info'
    )
    
    # Just pass through to the main script's logging function if it exists
    if (Get-Command Write-SimLog -ErrorAction SilentlyContinue) {
        Write-SimLog -Message $Message -Level $Level
    } else {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Write-Host "[$timestamp] [$Level] $Message"
    }
}

function Get-AesKey {
    param(
        [Parameter(Mandatory)]
        [string]$Password,
        
        [int]$KeySize = 256
    )
    
    # Generate a secure AES key from the provided password using SHA-256
    $sha = New-Object System.Security.Cryptography.SHA256Managed
    $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
    $keyBytes = $sha.ComputeHash($passwordBytes)
    
    # Return appropriate number of bytes for the key size
    $keySizeInBytes = $KeySize / 8
    if ($keyBytes.Length -gt $keySizeInBytes) {
        # Trim if SHA-256 output is larger than needed key size
        [byte[]]$result = $keyBytes[0..($keySizeInBytes - 1)]
    } elseif ($keyBytes.Length -lt $keySizeInBytes) {
        # Pad if SHA-256 output is smaller than needed key size (shouldn't happen with SHA-256)
        [byte[]]$result = New-Object byte[] $keySizeInBytes
        [Array]::Copy($keyBytes, $result, $keyBytes.Length)
    } else {
        [byte[]]$result = $keyBytes
    }
    
    return $result
}

function Get-AesIV {
    param(
        [Parameter(Mandatory)]
        [string]$Password
    )
    
    # Generate a 16-byte IV (initialization vector)
    # For demo purposes, we derive it from password
    $md5 = New-Object System.Security.Cryptography.MD5CryptoServiceProvider
    $passwordBytes = [System.Text.Encoding]::UTF8.GetBytes($Password)
    $ivBytes = $md5.ComputeHash($passwordBytes)
    
    # Return the first 16 bytes (128 bits) for the IV
    return $ivBytes
}
#endregion

#region Encryption Functions
function Protect-File {
    [Alias("Encrypt-File")]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [Parameter(Mandatory)]
        [string]$Password
    )
    
    Write-AesLog "Encrypting file: $FilePath" -Level Debug
    
    # Validate the file exists
    if (-not (Test-Path $FilePath)) {
        throw "File not found: $FilePath"
    }
    
    # Generate key and IV
    $key = Get-AesKey -Password $Password
    $iv = Get-AesIV -Password $Password
    
    # Create AES provider
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    # Setup encryption
    $encryptor = $aes.CreateEncryptor($aes.Key, $aes.IV)
      # Get file info for output path
    $originalFileInfo = New-Object System.IO.FileInfo($FilePath)
    $encryptedFilePath = "$FilePath.locked"
    
    try {
        # Create file streams
        $fsInput = New-Object System.IO.FileStream($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fsOutput = New-Object System.IO.FileStream($encryptedFilePath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        
        # Create cryptographic stream
        $csEncrypt = New-Object System.Security.Cryptography.CryptoStream($fsOutput, $encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
        
        # First, write the original file extension as metadata (for restoration)
        $extensionBytes = [System.Text.Encoding]::UTF8.GetBytes($originalFileInfo.Extension.PadRight(20, [char]0))
        $csEncrypt.Write($extensionBytes, 0, $extensionBytes.Length)
        
        # Read the input file and encrypt to output
        $bufferSize = 4096
        $buffer = New-Object byte[] $bufferSize
        
        $bytesRead = 0
        while (($bytesRead = $fsInput.Read($buffer, 0, $bufferSize)) -gt 0) {
            $csEncrypt.Write($buffer, 0, $bytesRead)
        }
        
        # Close streams
        $csEncrypt.FlushFinalBlock()
        $csEncrypt.Close()
        $fsInput.Close()
        $fsOutput.Close()
        
        Write-AesLog "File encrypted successfully: $FilePath -> $encryptedFilePath" -Level Success
        return $encryptedFilePath
    } catch {
        Write-AesLog "Encryption failed: $_" -Level Error
        throw "Failed to encrypt file: $_"
    } finally {
        # Clean up
        if ($aes) { $aes.Dispose() }
        if ($encryptor) { $encryptor.Dispose() }
        if ($csEncrypt) { $csEncrypt.Dispose() }
        if ($fsInput) { $fsInput.Close() }
        if ($fsOutput) { $fsOutput.Close() }
    }
}

function Unprotect-File {
    [Alias("Decrypt-File")]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        
        [Parameter(Mandatory)]
        [string]$Password,
        
        [string]$OutputPath = ""
    )
    
    Write-AesLog "Decrypting file: $FilePath" -Level Debug
    
    # Validate the file exists
    if (-not (Test-Path $FilePath)) {
        throw "File not found: $FilePath"
    }
    
    # Check if it's an encrypted file
    if (-not $FilePath.EndsWith(".locked")) {
        throw "Not an encrypted file: $FilePath"
    }
    
    # Generate key and IV
    $key = Get-AesKey -Password $Password
    $iv = Get-AesIV -Password $Password
    
    # Create AES provider
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256
    $aes.BlockSize = 128
    $aes.Key = $key
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    # Setup decryption
    $decryptor = $aes.CreateDecryptor($aes.Key, $aes.IV)
    
    # Determine output path
    if ([string]::IsNullOrEmpty($OutputPath)) {
        # Default output path removes the .locked extension
        $OutputPath = $FilePath.Substring(0, $FilePath.Length - ".locked".Length)
    }
    
    try {
        # Create file streams
        $fsInput = New-Object System.IO.FileStream($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        $fsOutput = New-Object System.IO.FileStream($OutputPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        
        # Create cryptographic stream
        $csDecrypt = New-Object System.Security.Cryptography.CryptoStream($fsInput, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Read)
        
        # Read the original file extension (20 bytes)
        $extensionBytes = New-Object byte[] 20
        $csDecrypt.Read($extensionBytes, 0, 20) | Out-Null
        $originalExtension = [System.Text.Encoding]::UTF8.GetString($extensionBytes).Trim([char]0)
        
        # Check if we need to update the output path based on the stored extension
        if (-not [string]::IsNullOrEmpty($originalExtension) -and -not $OutputPath.EndsWith($originalExtension)) {
            $fsOutput.Close()
            $OutputPath = $OutputPath + $originalExtension
            $fsOutput = New-Object System.IO.FileStream($OutputPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        }
        
        # Read the decrypted data and write to output file
        $bufferSize = 4096
        $buffer = New-Object byte[] $bufferSize
        
        $bytesRead = 0
        while (($bytesRead = $csDecrypt.Read($buffer, 0, $bufferSize)) -gt 0) {
            $fsOutput.Write($buffer, 0, $bytesRead)
        }
        
        # Close streams
        $csDecrypt.Close()
        $fsInput.Close()
        $fsOutput.Close()
        
        Write-AesLog "File decrypted successfully: $FilePath -> $OutputPath" -Level Success
        return $OutputPath
    } catch {
        Write-AesLog "Decryption failed: $_" -Level Error
        throw "Failed to decrypt file: $_"
    } finally {
        # Clean up
        if ($aes) { $aes.Dispose() }
        if ($decryptor) { $decryptor.Dispose() }
        if ($csDecrypt) { $csDecrypt.Dispose() }
        if ($fsInput) { $fsInput.Close() }
        if ($fsOutput) { $fsOutput.Close() }
    }
}
#endregion

#region Advanced Functions
function Test-AesModule {
    Write-AesLog "Testing AES module functionality..." -Level Info
    
    try {
        # Create a test file
        $testFilePath = [System.IO.Path]::GetTempFileName()
        $testContent = "This is a test file for AES encryption module. Generated at $(Get-Date)."
        Set-Content -Path $testFilePath -Value $testContent -Encoding UTF8
        
        # Test password
        $testPassword = "TestPassword123!"
        
        # Encrypt the file
        $encryptedPath = Encrypt-File -FilePath $testFilePath -Password $testPassword
        
        # Verify encrypted file exists
        if (-not (Test-Path $encryptedPath)) {
            throw "Encryption test failed: Encrypted file not found."
        }
        
        # Decrypt the file
        $decryptedPath = $testFilePath + ".decrypted"
        Decrypt-File -FilePath $encryptedPath -Password $testPassword -OutputPath $decryptedPath
        
        # Verify decrypted file exists
        if (-not (Test-Path $decryptedPath)) {
            throw "Decryption test failed: Decrypted file not found."
        }
        
        # Compare contents
        $decryptedContent = Get-Content -Path $decryptedPath -Encoding UTF8 -Raw
        if ($decryptedContent -ne $testContent) {
            throw "Content verification failed: Decrypted content doesn't match original."
        }
        
        # Clean up
        Remove-Item $testFilePath -Force -ErrorAction SilentlyContinue
        Remove-Item $encryptedPath -Force -ErrorAction SilentlyContinue
        Remove-Item $decryptedPath -Force -ErrorAction SilentlyContinue
        
        Write-AesLog "AES module test completed successfully!" -Level Success
        return $true
    } catch {
        Write-AesLog "AES module test failed: $_" -Level Error
        return $false
    }
}

function Protect-Text {
    [Alias("Encrypt-Text")]
    param(
        [Parameter(Mandatory)]
        [string]$Text,
        
        [Parameter(Mandatory)]
        [string]$Password
    )
    
    try {
        # Generate key and IV
        $key = Get-AesKey -Password $Password
        $iv = Get-AesIV -Password $Password
        
        # Create AES provider
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        # Setup encryption
        $encryptor = $aes.CreateEncryptor($aes.Key, $aes.IV)
        
        # Convert text to bytes
        $textBytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        
        # Encrypt bytes
        $encryptedBytes = $encryptor.TransformFinalBlock($textBytes, 0, $textBytes.Length)
        
        # Combine IV and encrypted data
        $combinedBytes = New-Object byte[] ($iv.Length + $encryptedBytes.Length)
        [Array]::Copy($iv, 0, $combinedBytes, 0, $iv.Length)
        [Array]::Copy($encryptedBytes, 0, $combinedBytes, $iv.Length, $encryptedBytes.Length)
        
        # Convert to Base64 for string representation
        $encryptedBase64 = [Convert]::ToBase64String($combinedBytes)
        
        return $encryptedBase64
    } catch {
        Write-AesLog "Text encryption failed: $_" -Level Error
        throw "Failed to encrypt text: $_"
    } finally {
        if ($aes) { $aes.Dispose() }
        if ($encryptor) { $encryptor.Dispose() }
    }
}

function Unprotect-Text {
    [Alias("Decrypt-Text")]
    param(
        [Parameter(Mandatory)]
        [string]$EncryptedText,
        
        [Parameter(Mandatory)]
        [string]$Password
    )
    
    try {
        # Convert Base64 to bytes
        $combinedBytes = [Convert]::FromBase64String($EncryptedText)
        
        # Extract IV and encrypted data
        $iv = New-Object byte[] 16
        $encryptedBytes = New-Object byte[] ($combinedBytes.Length - 16)
        [Array]::Copy($combinedBytes, 0, $iv, 0, 16)
        [Array]::Copy($combinedBytes, 16, $encryptedBytes, 0, $encryptedBytes.Length)
        
        # Generate key
        $key = Get-AesKey -Password $Password
        
        # Create AES provider
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.BlockSize = 128
        $aes.Key = $key
        $aes.IV = $iv
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        
        # Setup decryption
        $decryptor = $aes.CreateDecryptor($aes.Key, $aes.IV)
        
        # Decrypt bytes
        $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)
        
        # Convert bytes back to text
        $decryptedText = [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
        
        return $decryptedText
    } catch {
        Write-AesLog "Text decryption failed: $_" -Level Error
        throw "Failed to decrypt text: $_"
    } finally {
        if ($aes) { $aes.Dispose() }
        if ($decryptor) { $decryptor.Dispose() }
    }
}
#endregion

# Export module functions
Export-ModuleMember -Function Protect-File, Unprotect-File, Get-AesKey, Test-AesModule, Protect-Text, Unprotect-Text
# Export aliases to maintain compatibility
Export-ModuleMember -Alias Encrypt-File, Decrypt-File, Encrypt-Text, Decrypt-Text
