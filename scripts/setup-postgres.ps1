$ErrorActionPreference = 'Stop'
$projectDirectory = Split-Path $PSScriptRoot -Parent
$phpExecutable = Join-Path $env:USERPROFILE '.config\herd\bin\php83\php.exe'
$adminRole = Read-Host 'PostgreSQL administrator role [postgres]'
if ([string]::IsNullOrWhiteSpace($adminRole)) { $adminRole = 'postgres' }
$adminPassword = Read-Host 'PostgreSQL administrator password (hidden)' -AsSecureString
$passwordPointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($adminPassword)
try {
    $env:AETHER_PG_ADMIN = $adminRole
    $env:AETHER_PG_ADMIN_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPointer)
    Push-Location $projectDirectory
    try {
        & $phpExecutable (Join-Path $PSScriptRoot 'setup-postgres.php')
        if ($LASTEXITCODE -ne 0) { throw 'PostgreSQL setup did not complete. Existing MySQL is untouched.' }
    } finally { Pop-Location }
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPointer)
    Remove-Item Env:AETHER_PG_ADMIN_PASSWORD -ErrorAction SilentlyContinue
    Remove-Item Env:AETHER_PG_ADMIN -ErrorAction SilentlyContinue
}
