# BORRADOR de PoC. Ejecutar manualmente con el usuario de Docker Desktop.
# Mantiene los eventos Docker originales y añade identidad verificable para Grype.
# No instala servicios ni tareas. No ejecutar a la vez que otro colector sobre este archivo.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Context,
    [Parameter(Mandatory=$true)][string]$LogPath,
    [ValidateRange(1,3600)][int]$DurationSeconds = 300
)
$ErrorActionPreference = 'Stop'
$utf8 = [Text.UTF8Encoding]::new($false)
$dockerExe = (Get-Command docker.exe -ErrorAction Stop).Source
$parent = Split-Path -Parent $LogPath
if (!(Test-Path -LiteralPath $parent)) { throw 'Crear y autorizar primero la carpeta de salida y sus permisos.' }
$endAt = [DateTimeOffset]::UtcNow.AddSeconds($DurationSeconds).ToUnixTimeSeconds()
function Write-Event($Object) {
    $line = ConvertTo-Json -InputObject $Object -Depth 40 -Compress
    if ($utf8.GetByteCount($line) -gt 5500) { throw 'Evento demasiado grande; no se escribe una línea truncada.' }
    [IO.File]::AppendAllText($LogPath, $line + [Environment]::NewLine, $utf8)
}
function Get-DockerJson([string[]]$DockerArgs) {
    $raw = & $dockerExe --context $Context @DockerArgs 2>$null
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo inspeccionar el objeto Docker.' }
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
while ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt $endAt) {
    try {
        $engineId = & $dockerExe --context $Context info --format '{{.ID}}' 2>$null
        if ($LASTEXITCODE -ne 0 -or !$engineId) { throw 'Docker no está disponible.' }
        $streamStart = [DateTime]::UtcNow.ToString('o')
        & $dockerExe --context $Context events --since $streamStart --until "$endAt" --format '{{json .}}' 2>$null | ForEach-Object {
            $event = ConvertFrom-Json -InputObject $_
            $envelope = [ordered]@{ integration='docker'; docker=$event }
            $relevant = ($event.Type -eq 'image' -and $event.Action -eq 'pull') -or ($event.Type -eq 'container' -and $event.Action -in @('create','start'))
            if ($relevant) {
                $meta = [ordered]@{ engine_id=[string]$engineId; observed_at=[DateTime]::UtcNow.ToString('o'); event_type=[string]$event.Type; action=[string]$event.Action; identity_status='error' }
                try {
                    if ($event.Type -eq 'container') {
                        $container = Get-DockerJson @('container','inspect','--format','{{json .}}',[string]$event.Actor.ID)
                        $meta.image_ref = [string]$container.Config.Image
                        $image = Get-DockerJson @('image','inspect','--format','{{json .}}',[string]$container.Image)
                    } else {
                        $reference = [string]$event.Actor.ID
                        if (!$reference -or $reference -match '^sha256:') { $reference = [string]$event.Actor.Attributes.name }
                        if (!$reference -or $reference.StartsWith('-')) { throw 'Referencia no válida.' }
                        $meta.image_ref = $reference
                        $image = Get-DockerJson @('image','inspect','--format','{{json .}}',$reference)
                    }
                    $identity = Get-ImageIdentity $image
                    foreach ($key in $identity.Keys) { $meta[$key] = $identity[$key] }
                } catch { $meta.identity_status = 'inspection_failed' }
                $envelope.poc = $meta
            }
            Write-Event $envelope
        }
    } catch {
        Write-Event @{integration='poc_collector'; poc_collector=@{status='error'; detail='Docker o la escritura de eventos no están disponibles'; time=[DateTime]::UtcNow.ToString('o')}}
    }
    if ([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() -lt $endAt) { Start-Sleep -Seconds 5 }
}
