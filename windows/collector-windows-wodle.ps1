<#
.SYNOPSIS
  Colector de eventos de Docker Desktop para Wazuh, pensado para el wodle "command".

.DESCRIPTION
  Cada ejecución recoge los eventos nuevos del motor Docker desde la anterior, los
  añade a un fichero JSONL que el agente lee con <localfile> y termina. El wodle lo
  relanza en cada intervalo: no hay que lanzarlo ni pararlo a mano.

  Deriva de collector-windows.ps1 (paquete docker-windows-grype del 27 oct 2026). La
  lógica de identidad de la imagen (digest, plataforma) es la misma y el formato de
  las líneas también. Cambia el modo de funcionamiento:
    - ventana corta (--since/--until) en lugar de una captura continua de hasta 3600 s;
    - el punto de lectura se guarda en un fichero de estado: no se repiten ni se
      pierden eventos entre ejecuciones;
    - un mutex impide dos ejecuciones a la vez sobre el mismo fichero;
    - conecta por el named pipe del motor (-DockerHost), sin depender del contexto
      Docker del usuario, para poder correr como LocalSystem;
    - los errores de Docker se avisan una sola vez y se avisa también al recuperarse.

  Uso previsto: <wodle name="command"> con intervalo corto (ver windows/wodle.xml).
  Salida: JSONL en -LogPath; estado en -StatePath (por defecto <LogPath>.state.json).

.PARAMETER DockerHost
  Endpoint del motor. Por defecto, el named pipe del motor Linux de Docker Desktop.
.PARAMETER LookbackSeconds
  Solo en la primera ejecución (sin estado): cuántos segundos hacia atrás leer.
.PARAMETER MaxWindowSeconds
  Si pasó más tiempo que esto desde la última lectura (agente parado, Docker caído),
  no se recuperan los eventos más antiguos: se avisa con un evento "gap".
#>
[CmdletBinding()]
param(
    [string]$DockerHost = 'npipe:////./pipe/dockerDesktopLinuxEngine',
    [string]$LogPath = 'C:\WazuhPoC\runtime\docker-events.jsonl',
    [string]$StatePath,
    [ValidateRange(0,3600)][int]$LookbackSeconds = 0,
    [ValidateRange(10,86400)][int]$MaxWindowSeconds = 600
)
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
$nanoPerSecond = 1000000000L
if (-not $StatePath) { $StatePath = $LogPath + '.state.json' }

$dockerExe = (Get-Command docker.exe -ErrorAction SilentlyContinue).Source
if (-not $dockerExe) {
    $candidate = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    if (Test-Path -LiteralPath $candidate) { $dockerExe = $candidate }
}
if (-not $dockerExe) { throw 'No se encuentra docker.exe.' }
$parent = Split-Path -Parent $LogPath
if (!(Test-Path -LiteralPath $parent)) { throw 'Crear y autorizar primero la carpeta de salida y sus permisos.' }

# Una sola ejecución a la vez. Global\ vale entre sesiones (servicio y usuario). Si el
# mutex es de otra cuenta y no se puede abrir, también hay otra ejecución en curso.
$mutex = $null
$owned = $false
try {
    $mutex = New-Object System.Threading.Mutex($false, 'Global\WazuhDockerEventsCollector')
    try { $owned = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
} catch { $owned = $false }
if (-not $owned) {
    if ($mutex) { $mutex.Dispose() }
    Write-Output 'Otra ejecución del colector está en curso: se omite esta.'
    return
}

function Write-Event($Object) {
    $line = ConvertTo-Json -InputObject $Object -Depth 40 -Compress
    if ($utf8.GetByteCount($line) -gt 5500) { throw 'Evento demasiado grande; no se escribe una línea truncada.' }
    [IO.File]::AppendAllText($LogPath, $line + [Environment]::NewLine, $utf8)
}
function Write-CollectorStatus([string]$Status, [string]$Detail) {
    Write-Event @{integration='poc_collector'; poc_collector=@{status=$Status; detail=$Detail; time=[DateTime]::UtcNow.ToString('o')}}
}
function Invoke-Docker([string[]]$DockerArgs) {
    # En Windows PowerShell 5.1, con ErrorActionPreference=Stop el stderr de un ejecutable
    # nativo se convierte en excepción aunque se redirija a $null. Aquí se desactiva y
    # el resultado se comprueba con el código de salida ($script:dockerExit).
    $ErrorActionPreference = 'Continue'
    $out = & $dockerExe -H $DockerHost @DockerArgs 2>$null
    $script:dockerExit = $LASTEXITCODE
    return $out
}
function Get-DockerJson([string[]]$DockerArgs) {
    $raw = Invoke-Docker $DockerArgs
    if ($script:dockerExit -ne 0) { throw 'No se pudo inspeccionar el objeto Docker.' }
    return ConvertFrom-Json -InputObject ($raw -join [Environment]::NewLine)
}
function Get-ImageIdentity($Image) {
    $platform = [string]$Image.Os + '/' + [string]$Image.Architecture
    if ($Image.Variant) { $platform += '/' + [string]$Image.Variant }
    # Docker 29 puede devolver el digest del índice como Id. Seleccionar primero
    # el manifiesto instalado de la plataforma, usando el ID ya observado.
    $selected = Get-DockerJson @('image','inspect','--platform',$platform,'--format','{{json .}}',[string]$Image.Id)
    $identity = [ordered]@{platform=$platform; image_id=[string]$selected.Id; identity_kind='config'; identity_status='no_registry_digest'}
    if ($selected.Descriptor -and $selected.Descriptor.mediaType) {
        if ($selected.Descriptor.mediaType -notin @('application/vnd.oci.image.manifest.v1+json','application/vnd.docker.distribution.manifest.v2+json')) {
            throw 'No se ha resuelto un manifiesto de plataforma concreto.'
        }
        $identity.image_id = [string]$selected.Descriptor.digest
        $identity.identity_kind = 'manifest'
    }
    $digests = @($selected.RepoDigests | Where-Object { $_ -match '@sha256:[a-f0-9]{64}$' })
    if ($digests.Count -gt 0) {
        $identity.repo_digest = [string]$digests[0]
        $identity.identity_status = 'ok'
    }
    return $identity
}
function Read-State {
    if (Test-Path -LiteralPath $StatePath) {
        try {
            $state = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
            [void][long]::Parse([string]$state.last_nano)
            return $state
        } catch { }
    }
    return $null
}
function Save-State([long]$LastNano, [string]$Status) {
    $tmp = $StatePath + '.tmp'
    $json = ConvertTo-Json -InputObject ([ordered]@{last_nano=[string]$LastNano; status=$Status; updated=[DateTime]::UtcNow.ToString('o')}) -Compress
    [IO.File]::WriteAllText($tmp, $json, $utf8)
    Move-Item -LiteralPath $tmp -Destination $StatePath -Force
}

try {
    $state = Read-State
    $previousStatus = if ($state) { [string]$state.status } else { 'new' }

    # Una sola consulta da el ID del motor y su reloj. Todo el cálculo de ventanas usa el
    # reloj del motor (el de los eventos), no el de Windows, por si la VM se descuadra.
    $info = Invoke-Docker @('info', '--format', '{{.ID}}|{{.SystemTime}}')
    $infoOk = ($script:dockerExit -eq 0 -and $info)
    $nowSec = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $engineId = ''
    if ($infoOk) {
        $parts = ([string]$info).Trim().Split('|', 2)
        $engineId = $parts[0]
        try {
            $engineTime = $parts[1] -replace '(\.\d{1,7})\d*', '$1'
            $nowSec = [DateTimeOffset]::Parse($engineTime, [Globalization.CultureInfo]::InvariantCulture).ToUnixTimeSeconds()
        } catch { }
    }
    $untilNano = $nowSec * $nanoPerSecond
    if ($state) { $last = [long]::Parse([string]$state.last_nano) }
    else { $last = ($nowSec - $LookbackSeconds) * $nanoPerSecond - 1 }

    $failed = -not $infoOk
    $lines = @()
    if (-not $failed) {
        if ($previousStatus -eq 'error') { Write-CollectorStatus 'recovered' 'Docker vuelve a estar disponible' }
        if ($state -and ($untilNano - $last) -gt ($MaxWindowSeconds * $nanoPerSecond)) {
            $last = $untilNano - ($MaxWindowSeconds * $nanoPerSecond)
            Write-CollectorStatus 'gap' ('Ventana superior a {0} s: se omiten los eventos anteriores' -f $MaxWindowSeconds)
        }
        $fraction = $last % $nanoPerSecond
        $sinceArg = '{0}.{1}' -f (($last - $fraction) / $nanoPerSecond), ([string]$fraction).PadLeft(9, '0')
        # Con --until en el pasado el comando vuelca el histórico de la ventana y termina.
        $lines = @(Invoke-Docker @('events', '--since', $sinceArg, '--until', "$nowSec", '--format', '{{json .}}'))
        if ($script:dockerExit -ne 0) { $failed = $true }
    }

    if ($failed) {
        # Se avisa una sola vez al empezar el fallo; el punto de lectura no avanza.
        if ($previousStatus -ne 'error') { Write-CollectorStatus 'error' 'Docker o la escritura de eventos no están disponibles' }
        Save-State $last 'error'
        Write-Output 'Docker no disponible: sin cambios.'
    } else {
        $maxNano = $last
        $count = 0
        foreach ($line in $lines) {
            if (-not $line) { continue }
            try { $ev = ConvertFrom-Json -InputObject ([string]$line) } catch { continue }
            if ($null -ne $ev.timeNano) { $evNano = [long]$ev.timeNano } else { $evNano = [long]$ev.time * $nanoPerSecond }
            if ($evNano -le $last) { continue }
            $envelope = [ordered]@{ integration='docker'; docker=$ev }
            $relevant = ($ev.Type -eq 'image' -and $ev.Action -eq 'pull') -or ($ev.Type -eq 'container' -and $ev.Action -in @('create','start'))
            if ($relevant) {
                $meta = [ordered]@{ engine_id=[string]$engineId; observed_at=[DateTime]::UtcNow.ToString('o'); event_type=[string]$ev.Type; action=[string]$ev.Action; identity_status='error' }
                try {
                    if ($ev.Type -eq 'container') {
                        $container = Get-DockerJson @('container','inspect','--format','{{json .}}',[string]$ev.Actor.ID)
                        $meta.image_ref = [string]$container.Config.Image
                        $image = Get-DockerJson @('image','inspect','--format','{{json .}}',[string]$container.Image)
                    } else {
                        $reference = [string]$ev.Actor.ID
                        if (!$reference -or $reference -match '^sha256:') { $reference = [string]$ev.Actor.Attributes.name }
                        if (!$reference -or $reference.StartsWith('-')) { throw 'Referencia no válida.' }
                        $meta.image_ref = $reference
                        $image = Get-DockerJson @('image','inspect','--format','{{json .}}',$reference)
                    }
                    $identity = Get-ImageIdentity $image
                    foreach ($key in $identity.Keys) { $meta[$key] = $identity[$key] }
                } catch { $meta.identity_status = 'inspection_failed' }
                $envelope.poc = $meta
            }
            try { Write-Event $envelope }
            catch { Write-CollectorStatus 'error' 'Evento demasiado grande; se omite sin truncar' }
            if ($evNano -gt $maxNano) { $maxNano = $evNano }
            Save-State $maxNano 'ok'
            $count++
        }
        Save-State ([Math]::Max($maxNano, $untilNano - 1)) 'ok'
        Write-Output ('{0} evento(s) nuevo(s) hasta {1}' -f $count, [DateTimeOffset]::FromUnixTimeSeconds($nowSec).ToString('o'))
    }
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
