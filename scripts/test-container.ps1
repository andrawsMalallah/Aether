param([switch]$SkipBuild)
$ErrorActionPreference = 'Stop'
$repository = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location -LiteralPath $repository
$runName = 'aether-container-' + [guid]::NewGuid().ToString('N').Substring(0, 10)
$fixtureDirectory = Join-Path $repository "storage\app\$runName"
New-Item -ItemType Directory -Path $fixtureDirectory | Out-Null
Copy-Item -LiteralPath (Join-Path $repository 'config\filesystems.php') -Destination (Join-Path $fixtureDirectory 'filesystems-base.php')
Copy-Item -LiteralPath (Join-Path $repository 'tests\Container\fixture.php') -Destination $fixtureDirectory
Copy-Item -LiteralPath (Join-Path $repository 'tests\Container\filesystems.php') -Destination $fixtureDirectory
Copy-Item -LiteralPath (Join-Path $repository 'tests\Container\BoundedJob.php') -Destination $fixtureDirectory
[IO.File]::WriteAllText((Join-Path $fixtureDirectory 'fixture.ini'), "auto_prepend_file=/container-fixtures/BoundedJob.php`n", [Text.UTF8Encoding]::new($false))
$frontController = [IO.File]::ReadAllText((Join-Path $repository 'public\index.php'))
$drainFixture = @'
<?php
if (parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH) === '/container-drain') {
    file_put_contents('/tmp/container-drain-started', '1');
    sleep(8);
    header('Content-Type: text/plain');
    echo 'Drained';
    exit;
}
?>
'@
[IO.File]::WriteAllText((Join-Path $fixtureDirectory 'index.php'), $drainFixture + $frontController, [Text.UTF8Encoding]::new($false))

function Invoke-Docker {
    & docker @args
    if ($LASTEXITCODE -ne 0) { throw 'Container verification command failed. Inspect retained fixture resources.' }
}

function Get-DockerOutput {
    # Windows PowerShell treats redirected native stderr as an ErrorRecord.
    $ErrorActionPreference = 'Continue'
    & docker @args 2>&1 | ForEach-Object { $_.ToString() } | Out-String
    $script:dockerExitCode = $LASTEXITCODE
}

$postgres = 'postgres:18-bookworm@sha256:bbf83594798e144bff365a9c191c5d779f181fb3135902064ab8ff11918020fc'
$mailpit = 'axllent/mailpit@sha256:23fe39e81bde596a918000b3135c0f85dc8bb4c9ea6be274b051143f3e300387'
$storage = 'adobe/s3mock@sha256:ab01a6946750f451ca215a47e91030695b260e4003b8a5a6201d25029b8fca92'
$inventory = @{ name = $runName; directory = $fixtureDirectory; images = @($postgres, $mailpit, $storage); cleanup = 'Retained; no automatic removal' }
$inventory | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $fixtureDirectory 'inventory.json')
Write-Output "Isolated fixture inventory: $fixtureDirectory"
# Inspect BuildKit's actual context so parent-directory exceptions cannot
# silently reintroduce stale assets or host configuration into later COPYs.
$contextDirectory = Join-Path $fixtureDirectory 'build-context'
Invoke-Docker build --target context-audit --output "type=local,dest=$contextDirectory" .
$contextRoot = Join-Path $contextDirectory 'context'
foreach ($excludedPath in @('.env', '.env.testing', '.git', 'vendor', 'node_modules', 'storage', 'guide', 'AGENTS.md', 'bootstrap/cache', 'public/build', 'public/hot', 'public/storage', 'database/database.sqlite')) {
    if (Test-Path -LiteralPath (Join-Path $contextRoot $excludedPath)) {
        throw "Excluded build-context path present: $excludedPath"
    }
}
foreach ($requiredPath in @('bootstrap/app.php', 'bootstrap/providers.php', 'database/migrations', 'database/factories', 'database/seeders', 'public/index.php', 'public/.htaccess', 'resources/css', 'tests/Container/fixture.php')) {
    if (-not (Test-Path -LiteralPath (Join-Path $contextRoot $requiredPath))) {
        throw "Required build-context path missing: $requiredPath"
    }
}
Write-Output 'Build-context exclusions and required sources passed.'
if (-not $SkipBuild) { Invoke-Docker build --target runtime -t aether:packaging . }
Invoke-Docker pull $postgres
Invoke-Docker pull $mailpit
Invoke-Docker pull $storage
Invoke-Docker network create --internal $runName
Invoke-Docker network create "$runName-ingress"
$fixtureMount = "type=bind,source=$fixtureDirectory,target=/fixture"
Invoke-Docker run --name "$runName-environment" --network none --mount $fixtureMount --entrypoint php `
    -e "FIXTURE_DATABASE_HOST=$runName-db" -e "FIXTURE_MAIL_HOST=$runName-mail" -e "FIXTURE_STORAGE_HOST=$runName-s3" `
    aether:packaging /fixture/fixture.php environment
$runtimeEnvironment = Join-Path $fixtureDirectory 'runtime.env'
Invoke-Docker run -d --name "$runName-db" --network $runName --env-file (Join-Path $fixtureDirectory 'database.env') $postgres
Invoke-Docker run -d --name "$runName-mail" --network $runName $mailpit
Invoke-Docker run -d --name "$runName-s3" --network $runName `
    -e COM_ADOBE_TESTING_S3MOCK_STORE_INITIAL_BUCKETS=fixture -e COM_ADOBE_TESTING_S3MOCK_STORE_RETAIN_FILES_ON_EXIT=true $storage
$databaseReady = $false
for ($attempt = 0; $attempt -lt 40; $attempt++) {
    & docker exec "$runName-db" pg_isready -U fixture -d aether_container *> $null
    if ($LASTEXITCODE -eq 0) { $databaseReady = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $databaseReady) { throw 'Isolated database did not become ready.' }
$fixtureReadMount = "type=bind,source=$fixtureDirectory,target=/container-fixtures,readonly"
$filesystemMount = "type=bind,source=$(Join-Path $fixtureDirectory 'filesystems.php'),target=/var/www/html/config/filesystems.php,readonly"
$iniMount = "type=bind,source=$(Join-Path $fixtureDirectory 'fixture.ini'),target=/usr/local/etc/php/conf.d/fixture.ini,readonly"
$common = @('--network', $runName, '--env-file', $runtimeEnvironment, '--mount', $fixtureReadMount, '--mount', $filesystemMount, '--mount', $iniMount)
Invoke-Docker run --name "$runName-release" @common aether:packaging release
# The same production configuration must fail closed on unsafe overrides.
foreach ($setting in @('APP_DEBUG=true', 'SESSION_DRIVER=file', 'QUEUE_CONNECTION=sync', 'LOG_CHANNEL=single', 'AETHER_RETENTION_ENABLED=true', 'PASSPORT_PUBLIC_KEY=invalid')) {
    $failureName = "$runName-rejected-" + ($setting.Split('=')[0]).ToLower().Replace('_', '-')
    $failureOutput = Get-DockerOutput run --name $failureName @common -e $setting aether:packaging web
    if ($script:dockerExitCode -eq 0 -or $failureOutput.Trim() -ne 'Aether startup failed.') { throw "Unsafe startup configuration was not safely rejected: $($setting.Split('=')[0])." }
}
$webCommon = $common.Clone()
$webCommon[1] = "$runName-ingress"
$indexMount = "type=bind,source=$(Join-Path $fixtureDirectory 'index.php'),target=/var/www/html/public/index.php,readonly"
Invoke-Docker run -d --name "$runName-web" @webCommon --mount $indexMount -p '127.0.0.1::10000' aether:packaging web
Invoke-Docker network connect $runName "$runName-web"
$binding = & docker port "$runName-web" 10000/tcp
if ($LASTEXITCODE -ne 0) { throw 'Web port lookup failed.' }
$url = "http://$($binding.Trim())"
$webReady = $false
for ($attempt = 0; $attempt -lt 40; $attempt++) {
    try {
        $response = Invoke-WebRequest "$url/ready" -UseBasicParsing -TimeoutSec 4
        if ($response.StatusCode -eq 200 -and $response.Content -eq 'Ready') { $webReady = $true; break }
    } catch { Start-Sleep -Seconds 1 }
}
if (-not $webReady) { throw 'Container web readiness failed.' }
Invoke-Docker exec "$runName-web" sh -c 'test ! -e .env && test ! -e storage/oauth-private.key && test ! -e vendor/pestphp && test ! -e node_modules && test ! -w app && test ! -w public && test ! -w vendor && test -w bootstrap/cache && test -w storage/framework/views'
foreach ($path in @('/login', '/.well-known/openid-configuration', '/.well-known/jwks.json')) {
    $response = Invoke-WebRequest "$url$path" -UseBasicParsing -TimeoutSec 4
    if ($response.StatusCode -ne 200 -or $response.Headers['X-Content-Type-Options'] -ne 'nosniff') { throw 'Public route/header assertion failed.' }
}
foreach ($path in @('/.env', '/storage/oauth-private.key', '/vendor/autoload.php', '/other.php')) {
    try { $response = Invoke-WebRequest "$url$path" -UseBasicParsing -TimeoutSec 4; throw 'Private path unexpectedly served.' }
    catch [System.Net.WebException] { if ([int]$_.Exception.Response.StatusCode -lt 400) { throw } }
}
Invoke-Docker exec "$runName-web" php /container-fixtures/fixture.php produce
Invoke-Docker run -d --name "$runName-worker" @common aether:packaging worker
$verified = $false
for ($attempt = 0; $attempt -lt 60; $attempt++) {
    Get-DockerOutput exec "$runName-web" php /container-fixtures/fixture.php verify | Out-Null
    if ($script:dockerExitCode -eq 0) { $verified = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $verified) { throw 'Independent worker/shared export verification failed.' }
Invoke-Docker exec "$runName-web" php /container-fixtures/fixture.php download-session
Invoke-Docker exec "$runName-web" php /container-fixtures/fixture.php download-check
Invoke-Docker exec "$runName-web" php /container-fixtures/fixture.php expire
Invoke-Docker exec "$runName-web" php /container-fixtures/fixture.php expired-check
Invoke-Docker run --name "$runName-hourly" @common --entrypoint php aether:packaging /container-fixtures/fixture.php schedule-hour
Invoke-Docker exec "$runName-web" php /container-fixtures/fixture.php expiry-verify
Invoke-Docker run --name "$runName-scheduler" @common aether:packaging scheduler
Invoke-Docker exec "$runName-web" php /container-fixtures/fixture.php log
$logs = Get-DockerOutput logs "$runName-web"
if ($logs.Contains('CONTAINER_SENSITIVE_CANARY')) { throw 'Sensitive marker found in container logs.' }
# PostgreSQL outage must affect readiness without taking liveness down.
Invoke-Docker stop --timeout 10 "$runName-db"
$probeTimer = [Diagnostics.Stopwatch]::StartNew()
try { Invoke-WebRequest "$url/ready" -UseBasicParsing -TimeoutSec 5 | Out-Null; throw 'Readiness accepted database outage.' }
catch [System.Net.WebException] {
    if ([int]$_.Exception.Response.StatusCode -ne 503) { throw }
    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
    if ($reader.ReadToEnd() -ne 'Unavailable') { throw 'Readiness failure body changed.' }
}
if ($probeTimer.Elapsed.TotalSeconds -ge 5) { throw 'Readiness exceeded the platform health budget.' }
if ((Invoke-WebRequest "$url/up" -UseBasicParsing -TimeoutSec 4).StatusCode -ne 200) { throw 'Liveness depended on PostgreSQL.' }
Invoke-Docker start "$runName-db"
Start-Sleep -Seconds 3
$response = Invoke-WebRequest "$url/ready" -UseBasicParsing -TimeoutSec 4
if ($response.StatusCode -ne 200) { throw 'Readiness did not recover.' }
# Simulate the platform's worker restart policy after a lost DB connection.
Invoke-Docker restart "$runName-worker"
Invoke-Docker exec "$runName-web" php /container-fixtures/fixture.php drain-produce
$started = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    Get-DockerOutput exec "$runName-web" php /container-fixtures/fixture.php drain-started | Out-Null
    if ($script:dockerExitCode -eq 0) { $started = $true; break }
    Start-Sleep -Milliseconds 250
}
if (-not $started) { throw 'Bounded worker job never started.' }
$drainTimer = [Diagnostics.Stopwatch]::StartNew()
Invoke-Docker stop --timeout 115 "$runName-worker"
Invoke-Docker exec "$runName-web" php /container-fixtures/fixture.php drain-verify
if ($drainTimer.Elapsed.TotalSeconds -lt 3 -or $drainTimer.Elapsed.TotalSeconds -ge 115) { throw 'Worker did not drain within bounds.' }
$workerLogs = Get-DockerOutput logs "$runName-worker"
if ($workerLogs.Contains('CONTAINER_SENSITIVE_CANARY')) { throw 'Sensitive marker found in worker logs.' }
$workerSeconds = [math]::Round($drainTimer.Elapsed.TotalSeconds, 1)
$requestJob = Start-Job -ScriptBlock { param($requestUrl) (Invoke-WebRequest "$requestUrl/container-drain" -UseBasicParsing -TimeoutSec 20).Content } -ArgumentList $url
$requestStarted = $false
for ($attempt = 0; $attempt -lt 40; $attempt++) {
    Get-DockerOutput exec "$runName-web" test -e /tmp/container-drain-started | Out-Null
    if ($script:dockerExitCode -eq 0) { $requestStarted = $true; break }
    Start-Sleep -Milliseconds 250
}
if (-not $requestStarted) { throw 'Bounded HTTP request never started.' }
Invoke-Docker stop --timeout 115 "$runName-web"
$requestJob | Wait-Job -Timeout 25 | Out-Null
if (($requestJob | Receive-Job) -ne 'Drained') { throw 'Apache did not drain the in-flight request.' }
Write-Output "Worker graceful shutdown: $workerSeconds seconds; in-flight HTTP request drained."
Write-Output 'Container smoke passed. Fixtures retained for review; cleanup requires approval.'
