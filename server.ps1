# ============================================================================
#  Tide - local account server
#
#  A small, dependency-free PowerShell 5.1 / .NET HttpListener backend for the
#  Tide cycle tracker. It serves index.html and provides:
#
#    POST /api/auth/signup   create an account + session
#    POST /api/auth/login    sign in + session
#    POST /api/auth/logout   end the session
#    GET  /api/auth/me       restore the current session
#    GET  /api/data          read the signed-in user's cycle data
#    PUT  /api/data          save cycle data (optimistic revision check)
#    GET  /api/health        liveness probe
#
#  Accounts and data are kept in data/tide-server.json. Passwords are stored
#  as PBKDF2-SHA256 hashes with a random per-user salt. Sessions live in memory
#  and are carried by an HttpOnly, SameSite=Strict cookie.
#
#  Usage:
#    powershell -ExecutionPolicy Bypass -File .\server.ps1
#    then open http://127.0.0.1:8799/
#
#  Options:
#    -Port 8799     choose another loopback port
#    -NoBrowser     do not open a browser automatically
# ============================================================================

param(
  [int]$Port = 8799,
  [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'

$script:Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:DataDir = Join-Path $script:Root 'data'
$script:DataFile = Join-Path $script:DataDir 'tide-server.json'
$script:IndexFile = Join-Path $script:Root 'index.html'
$script:Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$script:MaxBodyBytes = 2 * 1024 * 1024
$script:SessionDays = 7
$script:Pbkdf2Iterations = 150000
$script:PasswordMin = 10
$script:PasswordMax = 200
$script:NameMax = 40

function Write-Log {
  param([string]$Message)
  Write-Host ('[{0}] {1}' -f (Get-Date).ToString('HH:mm:ss'), $Message)
}

# ---------------------------------------------------------------------------
#  General helpers
# ---------------------------------------------------------------------------
function ConvertTo-DeepHashtable {
  param($Value)
  if ($null -eq $Value) { return $null }
  if ($Value -is [System.Collections.IDictionary]) {
    $out = @{}
    foreach ($key in $Value.Keys) {
      $out[[string]$key] = ConvertTo-DeepHashtable $Value[$key]
    }
    return $out
  }
  if ($Value -is [System.Management.Automation.PSCustomObject]) {
    $out = @{}
    foreach ($property in $Value.PSObject.Properties) {
      $out[$property.Name] = ConvertTo-DeepHashtable $property.Value
    }
    return $out
  }
  if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string])) {
    $list = New-Object System.Collections.ArrayList
    foreach ($item in $Value) {
      [void]$list.Add((ConvertTo-DeepHashtable $item))
    }
    return ,$list.ToArray()
  }
  return $Value
}

function Get-NowIso {
  return [DateTime]::UtcNow.ToString('o')
}

function New-RandomBytes {
  param([int]$Length)
  $bytes = New-Object byte[] $Length
  $script:Rng.GetBytes($bytes)
  return $bytes
}

function New-RandomToken {
  $bytes = New-RandomBytes 32
  return ([Convert]::ToBase64String($bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function New-UserId {
  $bytes = New-RandomBytes 12
  return 'usr_' + ([Convert]::ToBase64String($bytes)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function Get-PasswordHash {
  param([string]$Password, [byte[]]$Salt, [int]$Iterations)
  $derive = New-Object System.Security.Cryptography.Rfc2898DeriveBytes(
    $Password,
    $Salt,
    $Iterations,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256
  )
  $hash = $derive.GetBytes(32)
  $derive.Dispose()
  return [Convert]::ToBase64String($hash)
}

function Test-HashEqual {
  param([string]$Left, [string]$Right)
  try {
    $a = [Convert]::FromBase64String($Left)
    $b = [Convert]::FromBase64String($Right)
  } catch {
    return $false
  }
  if ($a.Length -ne $b.Length) { return $false }
  $difference = 0
  for ($i = 0; $i -lt $a.Length; $i++) {
    $difference = $difference -bor ($a[$i] -bxor $b[$i])
  }
  return ($difference -eq 0)
}

function Test-ValidEmail {
  param([string]$Email)
  if ([string]::IsNullOrWhiteSpace($Email)) { return $false }
  if ($Email.Length -gt 254) { return $false }
  return ($Email -match '^[^\s@]+@[^\s@]+\.[^\s@]{2,}$')
}

# ---------------------------------------------------------------------------
#  Persistent store
# ---------------------------------------------------------------------------
$script:Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$script:DummySalt = New-RandomBytes 16
$script:DummyHash = Get-PasswordHash 'tide-dummy-password' $script:DummySalt $script:Pbkdf2Iterations
$script:Sessions = @{}
$script:RateLimits = @{}

function Initialize-Store {
  if (-not (Test-Path -LiteralPath $script:DataDir)) {
    [void](New-Item -ItemType Directory -Path $script:DataDir -Force)
  }

  $script:Store = @{
    version = 1
    createdAt = (Get-NowIso)
    updatedAt = (Get-NowIso)
    users = @()
  }

  if (-not (Test-Path -LiteralPath $script:DataFile)) {
    Save-Store
    return
  }

  try {
    $text = [System.IO.File]::ReadAllText($script:DataFile, $script:Utf8NoBom)
    $parsed = ConvertTo-DeepHashtable ($text | ConvertFrom-Json)
    if ($null -eq $parsed -or -not ($parsed -is [System.Collections.IDictionary]) -or -not $parsed.ContainsKey('users')) {
      throw 'Unexpected store shape.'
    }
    $script:Store = $parsed
    if (-not $script:Store.ContainsKey('version')) { $script:Store.version = 1 }
    if (-not $script:Store.ContainsKey('createdAt')) { $script:Store.createdAt = (Get-NowIso) }
    if (-not $script:Store.ContainsKey('updatedAt')) { $script:Store.updatedAt = (Get-NowIso) }
    if ($null -eq $script:Store.users) { $script:Store.users = @() }
    $script:Store.users = @($script:Store.users)

    foreach ($user in $script:Store.users) {
      if (-not $user.ContainsKey('id')) { $user.id = New-UserId }
      if (-not $user.ContainsKey('email')) { $user.email = '' }
      if (-not $user.ContainsKey('name')) { $user.name = '' }
      if (-not $user.ContainsKey('emailNorm')) { $user.emailNorm = ([string]$user.email).Trim().ToLowerInvariant() }
      if (-not $user.ContainsKey('passwordHash')) { $user.passwordHash = '' }
      if (-not $user.ContainsKey('salt')) { $user.salt = '' }
      if (-not $user.ContainsKey('iterations')) { $user.iterations = $script:Pbkdf2Iterations }
      if (-not $user.ContainsKey('createdAt')) { $user.createdAt = (Get-NowIso) }
      if (-not $user.ContainsKey('data')) { $user.data = $null }
      if (-not $user.ContainsKey('dataRevision')) { $user.dataRevision = 0 }
      if (-not $user.ContainsKey('dataUpdatedAt')) { $user.dataUpdatedAt = $null }
      $user.dataRevision = [int]$user.dataRevision
    }
  } catch {
    $backup = Join-Path $script:DataDir ('tide-server.corrupt-{0}.json' -f (Get-Date).ToString('yyyyMMdd-HHmmss'))
    try { Move-Item -LiteralPath $script:DataFile -Destination $backup -Force } catch { }
    Write-Log ('Could not read the existing store. Moved it to ' + $backup)
    Save-Store
  }
}

function Save-Store {
  $script:Store.updatedAt = Get-NowIso
  $json = ConvertTo-Json -InputObject $script:Store -Depth 24
  $temp = $script:DataFile + '.tmp'
  [System.IO.File]::WriteAllText($temp, $json, $script:Utf8NoBom)
  Move-Item -LiteralPath $temp -Destination $script:DataFile -Force
}

function Find-UserByEmail {
  param([string]$EmailNorm)
  foreach ($user in $script:Store.users) {
    if ($user.emailNorm -eq $EmailNorm) { return $user }
  }
  return $null
}

function Find-UserById {
  param([string]$Id)
  foreach ($user in $script:Store.users) {
    if ($user.id -eq $Id) { return $user }
  }
  return $null
}

function Get-PublicUser {
  param($User)
  return @{
    id = [string]$User.id
    email = [string]$User.email
    name = [string]$User.name
    createdAt = [string]$User.createdAt
  }
}

function Get-CleanName {
  param([string]$Name)
  if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
  $clean = $Name -replace '<[^>]*>', ' '
  $clean = ($clean -replace '[\u0000-\u001F\u007F<>]', '' -replace '\s+', ' ').Trim()
  if ($clean.Length -gt $script:NameMax) { $clean = $clean.Substring(0, $script:NameMax).Trim() }
  return $clean
}

# ---------------------------------------------------------------------------
#  Sessions + cookies
# ---------------------------------------------------------------------------
function New-Session {
  param($User)
  $token = New-RandomToken
  $script:Sessions[$token] = @{
    userId = [string]$User.id
    createdAtUtc = [DateTime]::UtcNow
    expiresAtUtc = [DateTime]::UtcNow.AddDays($script:SessionDays)
  }
  return $token
}

function Get-SessionToken {
  param($Request)
  $cookie = $Request.Headers['Cookie']
  if ([string]::IsNullOrWhiteSpace($cookie)) { return $null }
  foreach ($part in $cookie.Split(';')) {
    $pair = $part.Trim()
    if ($pair.StartsWith('tide_session=')) {
      return $pair.Substring(13).Trim()
    }
  }
  return $null
}

function Get-AuthContext {
  param($Request)
  $token = Get-SessionToken $Request
  if ([string]::IsNullOrWhiteSpace($token)) { return $null }
  if (-not $script:Sessions.ContainsKey($token)) { return $null }
  $session = $script:Sessions[$token]
  if ($session.expiresAtUtc -lt [DateTime]::UtcNow) {
    $script:Sessions.Remove($token)
    return $null
  }
  $user = Find-UserById $session.userId
  if ($null -eq $user) {
    $script:Sessions.Remove($token)
    return $null
  }
  return @{ token = $token; user = $user; session = $session }
}

function Add-SessionCookie {
  param($Response, [string]$Token, [int]$MaxAgeSeconds)
  $value = 'tide_session={0}; Path=/; HttpOnly; SameSite=Strict; Max-Age={1}' -f $Token, $MaxAgeSeconds
  $Response.Headers.Add('Set-Cookie', $value)
}

# ---------------------------------------------------------------------------
#  Login throttling
# ---------------------------------------------------------------------------
function Get-RateEntry {
  param([string]$Key)
  $now = [DateTime]::UtcNow
  if (-not $script:RateLimits.ContainsKey($Key)) {
    $script:RateLimits[$Key] = @{
      count = 0
      windowStartUtc = $now
      blockedUntilUtc = [DateTime]::MinValue
    }
  }
  $entry = $script:RateLimits[$Key]
  if ($entry.blockedUntilUtc -and $entry.blockedUntilUtc -gt $now) { return $entry }
  if (($now - $entry.windowStartUtc).TotalMinutes -ge 10) {
    $entry.count = 0
    $entry.windowStartUtc = $now
    $entry.blockedUntilUtc = [DateTime]::MinValue
  }
  return $entry
}

function Get-RetryAfterSeconds {
  param($Entry)
  if ($Entry.blockedUntilUtc -le [DateTime]::UtcNow) { return 0 }
  return [int][Math]::Ceiling(($Entry.blockedUntilUtc - [DateTime]::UtcNow).TotalSeconds)
}

function Register-AuthFailure {
  param([string]$Key)
  $entry = Get-RateEntry $Key
  $entry.count = [int]$entry.count + 1
  if ($entry.count -ge 8) {
    $entry.blockedUntilUtc = [DateTime]::UtcNow.AddMinutes(5)
  }
}

function Clear-AuthFailures {
  param([string]$Key)
  if ($script:RateLimits.ContainsKey($Key)) { $script:RateLimits.Remove($Key) }
}

# ---------------------------------------------------------------------------
#  HTTP helpers
# ---------------------------------------------------------------------------
function Set-SecurityHeaders {
  param($Response)
  $Response.Headers['Cache-Control'] = 'no-store'
  $Response.Headers['X-Content-Type-Options'] = 'nosniff'
  $Response.Headers['X-Frame-Options'] = 'DENY'
  $Response.Headers['Referrer-Policy'] = 'no-referrer'
  $Response.Headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
}

function Write-JsonResponse {
  param($Response, [int]$Status, $Payload)
  $json = ConvertTo-Json -InputObject $Payload -Depth 24 -Compress
  $bytes = $script:Utf8NoBom.GetBytes($json)
  $Response.StatusCode = $Status
  $Response.ContentType = 'application/json; charset=utf-8'
  $Response.ContentLength64 = $bytes.Length
  $Response.OutputStream.Write($bytes, 0, $bytes.Length)
}

function Write-ErrorJson {
  param($Response, [int]$Status, [string]$Message)
  Write-JsonResponse $Response $Status @{ error = $Message }
}

function Read-JsonBody {
  param($Request, $Response)
  if ($Request.ContentLength64 -gt $script:MaxBodyBytes) {
    Write-ErrorJson $Response 413 'That request is too large.'
    return $null
  }
  $contentType = [string]$Request.ContentType
  if ([string]::IsNullOrWhiteSpace($contentType) -or -not $contentType.StartsWith('application/json', [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-ErrorJson $Response 415 'Expected a JSON request body.'
    return $null
  }
  try {
    $reader = New-Object System.IO.StreamReader($Request.InputStream, $script:Utf8NoBom)
    $text = $reader.ReadToEnd()
    $reader.Dispose()
    if ([string]::IsNullOrWhiteSpace($text)) {
      Write-ErrorJson $Response 400 'The request body is empty.'
      return $null
    }
    if ($text.Length -gt $script:MaxBodyBytes) {
      Write-ErrorJson $Response 413 'That request is too large.'
      return $null
    }
    $parsed = ConvertTo-DeepHashtable ($text | ConvertFrom-Json)
    if ($null -eq $parsed -or -not ($parsed -is [System.Collections.IDictionary])) {
      Write-ErrorJson $Response 400 'The request body must be a JSON object.'
      return $null
    }
    return $parsed
  } catch {
    Write-ErrorJson $Response 400 'That was not valid JSON.'
    return $null
  }
}

function Test-CycleDataShape {
  param($Data)
  if ($null -eq $Data -or -not ($Data -is [System.Collections.IDictionary])) { return $false }
  if (-not $Data.ContainsKey('periods') -or $null -eq $Data.periods) { return $false }
  if (-not $Data.ContainsKey('logs') -or -not ($Data.logs -is [System.Collections.IDictionary])) { return $false }
  if (-not $Data.ContainsKey('settings') -or -not ($Data.settings -is [System.Collections.IDictionary])) { return $false }
  $periods = @($Data.periods)
  if ($periods.Count -gt 2000) { return $false }
  $logCount = 0
  foreach ($key in $Data.logs.Keys) { $logCount++ }
  if ($logCount -gt 5000) { return $false }
  foreach ($period in $periods) {
    if (-not ($period -is [System.Collections.IDictionary])) { return $false }
    if (-not $period.ContainsKey('start')) { return $false }
    if (-not ([string]$period.start -match '^\d{4}-\d{2}-\d{2}$')) { return $false }
  }
  return $true
}

function Get-ClientAddress {
  param($Request)
  if ($null -eq $Request.RemoteEndPoint) { return 'local' }
  return [string]$Request.RemoteEndPoint.Address
}

# ---------------------------------------------------------------------------
#  API routes
# ---------------------------------------------------------------------------
function Send-SessionPayload {
  param($Response, $User, [int]$Status)
  Write-JsonResponse $Response $Status @{
    user = (Get-PublicUser $User)
    data = $User.data
    revision = [int]$User.dataRevision
    updatedAt = $User.dataUpdatedAt
  }
}

function Handle-Signup {
  param($Request, $Response)
  $body = Read-JsonBody $Request $Response
  if ($null -eq $body) { return }

  $email = ''
  $password = ''
  $name = ''
  if ($body.ContainsKey('email')) { $email = [string]$body.email }
  if ($body.ContainsKey('password')) { $password = [string]$body.password }
  if ($body.ContainsKey('name')) { $name = Get-CleanName ([string]$body.name) }
  $email = $email.Trim()

  if (-not (Test-ValidEmail $email)) {
    Write-ErrorJson $Response 400 'Enter a valid email address.'
    return
  }
  if ($password.Length -lt $script:PasswordMin) {
    Write-ErrorJson $Response 400 ('Use at least {0} characters for your password.' -f $script:PasswordMin)
    return
  }
  if ($password.Length -gt $script:PasswordMax) {
    Write-ErrorJson $Response 400 'That password is too long.'
    return
  }

  $emailNorm = $email.ToLowerInvariant()
  if ($null -ne (Find-UserByEmail $emailNorm)) {
    Write-ErrorJson $Response 409 'An account with that email already exists.'
    return
  }

  $salt = New-RandomBytes 16
  $hash = Get-PasswordHash $password $salt $script:Pbkdf2Iterations
  $user = @{
    id = New-UserId
    email = $email
    name = $name
    emailNorm = $emailNorm
    passwordHash = $hash
    salt = [Convert]::ToBase64String($salt)
    iterations = $script:Pbkdf2Iterations
    createdAt = Get-NowIso
    data = $null
    dataRevision = 0
    dataUpdatedAt = $null
  }
  $script:Store.users = @($script:Store.users) + @($user)
  Save-Store

  $token = New-Session $user
  Add-SessionCookie $Response $token ($script:SessionDays * 86400)
  Write-Log ('New account: ' + $emailNorm)
  Send-SessionPayload $Response $user 201
}

function Handle-Login {
  param($Request, $Response)
  $client = Get-ClientAddress $Request
  $entry = Get-RateEntry $client
  if ($entry.blockedUntilUtc -gt [DateTime]::UtcNow) {
    $retry = Get-RetryAfterSeconds $entry
    $Response.Headers['Retry-After'] = [string]$retry
    Write-ErrorJson $Response 429 ('Too many attempts. Try again in {0} seconds.' -f $retry)
    return
  }

  $body = Read-JsonBody $Request $Response
  if ($null -eq $body) { return }

  $email = ''
  $password = ''
  if ($body.ContainsKey('email')) { $email = [string]$body.email }
  if ($body.ContainsKey('password')) { $password = [string]$body.password }
  $emailNorm = $email.Trim().ToLowerInvariant()

  if (-not (Test-ValidEmail $email) -or [string]::IsNullOrEmpty($password)) {
    Register-AuthFailure $client
    Write-ErrorJson $Response 401 'Email or password is incorrect.'
    return
  }

  $user = Find-UserByEmail $emailNorm
  if ($null -eq $user) {
    # Keep the timing similar for unknown accounts.
    [void](Test-HashEqual (Get-PasswordHash $password $script:DummySalt $script:Pbkdf2Iterations) $script:DummyHash)
    Register-AuthFailure $client
    Write-ErrorJson $Response 401 'Email or password is incorrect.'
    return
  }

  $salt = [Convert]::FromBase64String([string]$user.salt)
  $candidate = Get-PasswordHash $password $salt ([int]$user.iterations)
  if (-not (Test-HashEqual $candidate ([string]$user.passwordHash))) {
    Register-AuthFailure $client
    Write-ErrorJson $Response 401 'Email or password is incorrect.'
    return
  }

  Clear-AuthFailures $client
  $token = New-Session $user
  Add-SessionCookie $Response $token ($script:SessionDays * 86400)
  Write-Log ('Signed in: ' + $emailNorm)
  Send-SessionPayload $Response $user 200
}

function Handle-Logout {
  param($Request, $Response)
  $token = Get-SessionToken $Request
  if (-not [string]::IsNullOrWhiteSpace($token) -and $script:Sessions.ContainsKey($token)) {
    $script:Sessions.Remove($token)
  }
  Add-SessionCookie $Response '' 0
  Write-JsonResponse $Response 200 @{ ok = $true }
}

function Handle-Me {
  param($Request, $Response)
  $auth = Get-AuthContext $Request
  if ($null -eq $auth) {
    Write-ErrorJson $Response 401 'Not signed in.'
    return
  }
  Send-SessionPayload $Response $auth.user 200
}

function Handle-GetData {
  param($Request, $Response)
  $auth = Get-AuthContext $Request
  if ($null -eq $auth) {
    Write-ErrorJson $Response 401 'Not signed in.'
    return
  }
  Write-JsonResponse $Response 200 @{
    data = $auth.user.data
    revision = [int]$auth.user.dataRevision
    updatedAt = $auth.user.dataUpdatedAt
  }
}

function Handle-PutData {
  param($Request, $Response)
  $auth = Get-AuthContext $Request
  if ($null -eq $auth) {
    Write-ErrorJson $Response 401 'Not signed in.'
    return
  }

  $body = Read-JsonBody $Request $Response
  if ($null -eq $body) { return }

  if (-not $body.ContainsKey('revision') -or -not $body.ContainsKey('data')) {
    Write-ErrorJson $Response 400 'A revision and data payload are required.'
    return
  }

  $revision = -1
  try { $revision = [int]$body.revision } catch { $revision = -1 }
  if ($revision -lt 0) {
    Write-ErrorJson $Response 400 'The revision must be a non-negative integer.'
    return
  }

  if ($revision -ne [int]$auth.user.dataRevision) {
    Write-JsonResponse $Response 409 @{
      error = 'conflict'
      message = 'This account was updated somewhere else.'
      data = $auth.user.data
      revision = [int]$auth.user.dataRevision
      updatedAt = $auth.user.dataUpdatedAt
    }
    return
  }

  if (-not (Test-CycleDataShape $body.data)) {
    Write-ErrorJson $Response 400 'That cycle data is not in a valid shape.'
    return
  }

  $auth.user.data = $body.data
  $auth.user.dataRevision = [int]$auth.user.dataRevision + 1
  $auth.user.dataUpdatedAt = Get-NowIso
  Save-Store

  Write-JsonResponse $Response 200 @{
    revision = [int]$auth.user.dataRevision
    updatedAt = $auth.user.dataUpdatedAt
  }
}

# ---------------------------------------------------------------------------
#  Static files + router
# ---------------------------------------------------------------------------
function Send-Index {
  param($Request, $Response)
  if (-not (Test-Path -LiteralPath $script:IndexFile)) {
    Write-ErrorJson $Response 500 'index.html is missing from the app folder.'
    return
  }
  $bytes = [System.IO.File]::ReadAllBytes($script:IndexFile)
  $Response.StatusCode = 200
  $Response.ContentType = 'text/html; charset=utf-8'
  $Response.ContentLength64 = $bytes.Length
  $Response.Headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
  if ($Request.HttpMethod -ne 'HEAD') {
    $Response.OutputStream.Write($bytes, 0, $bytes.Length)
  }
}

function Handle-Request {
  param($Context)
  $request = $Context.Request
  $response = $Context.Response
  Set-SecurityHeaders $response

  $method = $request.HttpMethod.ToUpperInvariant()
  $path = $request.Url.AbsolutePath.ToLowerInvariant()

  if ($method -eq 'OPTIONS') {
    $response.Headers['Allow'] = 'GET, POST, PUT, OPTIONS'
    $response.StatusCode = 204
    return
  }

  if ($path -eq '/api/health') {
    if ($method -ne 'GET') { Write-ErrorJson $response 405 'Use GET for this endpoint.'; return }
    Write-JsonResponse $response 200 @{ ok = $true; app = 'tide'; version = 1 }
    return
  }

  if ($path -eq '/api/auth/signup') {
    if ($method -ne 'POST') { Write-ErrorJson $response 405 'Use POST for this endpoint.'; return }
    Handle-Signup $request $response
    return
  }

  if ($path -eq '/api/auth/login') {
    if ($method -ne 'POST') { Write-ErrorJson $response 405 'Use POST for this endpoint.'; return }
    Handle-Login $request $response
    return
  }

  if ($path -eq '/api/auth/logout') {
    if ($method -ne 'POST') { Write-ErrorJson $response 405 'Use POST for this endpoint.'; return }
    Handle-Logout $request $response
    return
  }

  if ($path -eq '/api/auth/me') {
    if ($method -ne 'GET') { Write-ErrorJson $response 405 'Use GET for this endpoint.'; return }
    Handle-Me $request $response
    return
  }

  if ($path -eq '/api/data') {
    if ($method -eq 'GET') { Handle-GetData $request $response; return }
    if ($method -eq 'PUT') { Handle-PutData $request $response; return }
    Write-ErrorJson $response 405 'Use GET or PUT for this endpoint.'
    return
  }

  if ($path -eq '/' -or $path -eq '/index.html') {
    if ($method -ne 'GET' -and $method -ne 'HEAD') {
      Write-ErrorJson $response 405 'Use GET for this page.'
      return
    }
    Send-Index $request $response
    return
  }

  if ($path -eq '/favicon.ico') {
    $response.StatusCode = 204
    return
  }

  Write-JsonResponse $response 404 @{ error = 'Not found.' }
}

# ---------------------------------------------------------------------------
#  Start
# ---------------------------------------------------------------------------
Initialize-Store

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add(('http://127.0.0.1:{0}/' -f $Port))
try {
  $listener.Start()
} catch {
  Write-Host ''
  Write-Host 'Tide could not start the local server.' -ForegroundColor Red
  Write-Host ('  ' + $_.Exception.Message) -ForegroundColor Red
  Write-Host ''
  Write-Host ('The address http://127.0.0.1:{0}/ may already be in use.' -f $Port)
  Write-Host 'Close the other copy, or start this one with:  .\server.ps1 -Port 8800'
  exit 1
}

$url = ('http://127.0.0.1:{0}/' -f $Port)
Write-Host ''
Write-Host '  Tide is running' -ForegroundColor Magenta
Write-Host ('  Open {0}' -f $url) -ForegroundColor Cyan
Write-Host ('  Accounts and data: {0}' -f $script:DataFile)
Write-Host '  Press Ctrl+C to stop.'
Write-Host ''

if (-not $NoBrowser) {
  try { Start-Process $url } catch { }
}

try {
  while ($listener.IsListening) {
    $context = $null
    try {
      $context = $listener.GetContext()
    } catch {
      if (-not $listener.IsListening) { break }
      continue
    }
    try {
      Handle-Request $context
    } catch {
      try {
        Write-ErrorJson $context.Response 500 'Something went wrong on the server.'
      } catch { }
      Write-Log ('Request error: ' + $_.Exception.Message)
    } finally {
      try { $context.Response.Close() } catch { }
    }
  }
} finally {
  try { $listener.Stop() } catch { }
  try { $listener.Close() } catch { }
  $script:Rng.Dispose()
  Write-Host ''
  Write-Host 'Tide server stopped.' -ForegroundColor Magenta
}
