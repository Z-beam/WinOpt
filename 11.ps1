<#
Цей скрипт не рекомендується до виконання нікому. 
Будь-що ви робите на власний ризик. Будь-які зміни в системі можуть викликати проблеми.

Детально вивчіть код, щоб розуміти, що він виконує.
#>
Write-Host -ForegroundColor Yellow "


                                         
                                         
                                         
            ########    ########         
            ########    ########         
        ########################         
        ########################         
        ########################         
            ########    ########         
            ########    ########         
            ########    ########         
            ########    ########         
            ########    ########         
            ########    ########         
            ########    ########         
            ########    ########         
            ########    ########         
            ########    ########         
                                         
                                         
                                         
                                         
"

# Створення LOG-файлу для зневадження
Start-Transcript -Append C:\Support\Logs\WindowsSetupLog.txt

#ініціюємо змінні для роботи скрипта
$diskProps = (Get-PhysicalDisk | where size -gt 100gb)
$cortanaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$HighPerf = powercfg -l | %{if($_.contains("High performance")) {$_.split()[3]}}
$confirmUac = 'n'
$confirmInfo = 'n'
$confirmPower = 'n'
$confirmDev = 'n'
$avCheck = $false
$installCheck = 'n'
$officeCheck = $false

#додаємо F8 для завантаження у безпечний режим. Дає змогу якщо Windows перестане завантажуватись перейти у безпечний режим натисканням F8 під час запуску Windows як у старіших версіях.
Write-Host -ForegroundColor DarkMagenta "Виставляємо меню завантаження у legacy"
bcdedit /set "{current}" bootmenupolicy legacy

#Виставляємо ліміт для точок відновлення у 5% від об'єму диска
Write-Host -ForegroundColor DarkMagenta "Виставляємо ліміт для точок відновлення у 5%"
vssadmin resize shadowstorage /for=C: /on=C: /maxsize=5%

# Вмикаємо відновлення системи на C:\
Write-Host -ForegroundColor DarkMagenta "Вмикаємо відновлення системи на C:\"
Enable-ComputerRestore -Drive "$env:SystemDrive"

#Примусове створення точок відновлення по запиту
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /V "SystemRestorePointCreationFrequency" /T REG_DWORD /D 0 /F

#Створення точки відновлення перед застосуванням скрипта
Checkpoint-Computer -Description "До застосування скрипта" -RestorePointType "MODIFY_SETTINGS"

#Налаштовуємо план споживання. Гібернацію та режим сну вимикаю (0 - це вимкнути), для монітора даємо час 30 хвилин від мережі, та 20 хвилин від батареї до вимкнення 
Write-Host -ForegroundColor DarkMagenta "Налаштовуємо план живлення"
powercfg.exe -change -monitor-timeout-ac 30
powercfg.exe -change -monitor-timeout-dc 20
powercfg.exe -change -disk-timeout-ac 0
powercfg.exe -change -disk-timeout-dc 0
powercfg.exe -change -standby-timeout-ac 0
powercfg.exe -change -standby-timeout-dc 0
powercfg.exe -change -hibernate-timeout-ac 0
powercfg.exe -change -hibernate-timeout-dc 0

<#
#Вмикаємо старі версії .NET Framework. Для тих хто користується дуже старими застосунками чи іграми
Write-Host -ForegroundColor DarkMagenta "Enable .NET Framework"
Enable-WindowsOptionalFeature -Online -FeatureName NetFx3 -All
#>

#Вимкнення NBT-NS
#NBT-NS є старою, але все ще корисною технологією для розв'язання імен у локальних мережах, особливо для забезпечення сумісності з застарілими системами. 
#Якщо у вашій мережі немає застарілих систем, то задля безпеки NBT-NS краще вимкнути. 
Write-Host -ForegroundColor DarkMagenta "Вимкнення NBT-NS"
$regkey = "HKLM:SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces"
Get-ChildItem $regkey |foreach { Set-ItemProperty -Path "$regkey\$($_.pschildname)" -Name NetbiosOptions -Value 2 -Verbose}

#Увімкнення SMB підпису як 'always'. Збільшує витрати на обробку даних всередині мережі, та не дає змоги під'єднатись старим пристроям, які не підтримують підпис SMB.
#З іншого боку включення SMB підпису з параметром "always" забезпечує вищий рівень безпеки шляхом захисту від атак типу MITM і забезпечення цілісності даних.
#Якщо не користуєтесь локальними мережами, або для вас безпека в мережі важливіша за невелику втрату швидкості, то цей пункт краще увімкнути.
Write-Host -ForegroundColor DarkMagenta "Увімкнення SMB підпису як 'always'"
$Parameters = @{
    RequireSecuritySignature = $True
    EnableSecuritySignature = $True
    EncryptData = $True
    Confirm = $false
}
Set-SmbServerConfiguration @Parameters

#Встановимо затримку блокування акаунта на 30 хвилин після 5 неправильно введених паролів.
#Це унеможливить безпосередній злам ПК за допомогою BruteForce
Write-Host -ForegroundColor DarkMagenta "Встановлюємо правила безпеки акаунта:"
Write-Host -ForegroundColor DarkMagenta "Заблокувати введення пароля на 30 хвилин `n після 5 невдалих спроб:"
net accounts /lockoutthreshold:5
#Встановлюємо період блокування в хв.
net accounts /lockoutduration:30
#Встановлюємо час через який можна буде вводити пароль знову в хв.
net accounts /lockoutwindow:30

##########Прості доповнення##########

#Якщо у вас досить потужний процесор та швидкий SSD, то є сенс прибрати затримку при завантаженні системи, щоб все, що мало завантажитись у пам'ять при автозавантаженні робило це одночасно.
#Це робить трохи довшим запуск системи та створює більше навантаження при запуску
#Якщо ви побачите робочий стіл, значить ви вже маєте повністю готову до роботи систему, нічого у фоні не підвантажується.
#Не рекомендується для слабких ПК, або для людей, яким 10-15 секунд у швидкості завантаження системи важливіші за зручність
Write-Host -ForegroundColor DarkMagenta "Вмикаємо запуск всього одночасно при вході користувача"
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /V "Startupdelayinmsec" /T REG_DWORD /D 0 /F

#######Chocolatey###########
Write-Host -ForegroundColor DarkMagenta "Встановлюємо Chocolatey для автоматизації встановлення простих застосунків"
#Встановлюємо Chocolatey та інші застосунки
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
	choco install chocolatey-core.extension -y

#Встановлюємо пошук Everything. Він швидший та ефективніший за стандартний
    choco install everything -y

#Встановлюємо браузер Firefox
    choco install firefox -y

#Встановлюємо браузер Chrome
    choco install googlechrome -y --ignore-checksums

#Встановлюємо читач PDF Okular
    choco install okular -y

#Встановлюємо архіватор 7-zip
    choco install 7zip -y
	
#Встановлюємо додаток для швидкого завершення задач SuperF4
    choco install superf4 -y
	
#Встановлюємо меню правої кнопки миші від Nilesoft-Shell
	choco install nilesoft-shell -y
	
#Встановлюємо Power Toys	
	choco install powertoys -y
	
#Встановлюємо швидкий переглядач файлів QuickLook	
	choco install quicklook -y
	
#Встановлюємо Everything плагін для PowerToys, щоб швидко шукати через Run
	choco install everythingpowertoys -y

#Встановлюємо медіаплеєр MPV
	choco install mpv -y

#Встановлюємо переглядач зображень FastStone
	choco install fsviewer -y
	
#Встановлюємо видяляч програм BCU
	choco install bulk-crap-uninstaller -y
	
#Встановлюємо правильний блокнот Notepad++
	choco install notepadplusplus.install -y
	
	choco install zoom -y
	
# Встановлення Mova прямо у автозавантаження
$exeUrl = "https://github.com/Z-beam/MovaFlag/releases/download/1.0.2/Mova.exe"
$downloadPath = "$env:USERPROFILE\Mova\Mova.exe"

# Створення директорії для збереження файлу, якщо її ще не існує
$destinationFolder = "$env:USERPROFILE\Mova"
if (-Not (Test-Path -Path $destinationFolder)) {
    New-Item -ItemType Directory -Path $destinationFolder
}

# Завантаження виконуваного файлу з GitHub
Invoke-WebRequest -Uri $exeUrl -OutFile $downloadPath

# Прописуємо шлях до автозавантаження
$startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
$shortcutPath = "$startupFolder\Mova.lnk"

# Створення ярлика в автозавантаженні
$WScriptShell = New-Object -ComObject WScript.Shell
$shortcut = $WScriptShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $downloadPath
$shortcut.Save()

# Виведення повідомлення про успішне завершення
 Write-Host  -ForegroundColor DarkMagenta "Mova успішно завантажено та додано до автозавантаження."


#Застереження про страшні червоні помилки, що можуть бути далі
Write-Warning "Помилки на цьому етапі можуть бути з двох причин `n1 Сервіс вже і так в ручному режимі `n2 Пакунок AppX не встановлено"
Start-Sleep 15

    Write-Host  -ForegroundColor DarkMagenta "Запускаємо O&O Shutup, щоб вимкнути телеметрію, Copilot, Recall"
#Попереду одне із моїх дивних рішень. Щоб не завантажувати файл конфігурації телеметрії для застосунка O&O Shutup, я просто його зчитаю прямо з цього файла та запишу у окремий файл. Таким чином ми викличемо вимкнення телеметрії завантаживши лише O&O Shutup. І файл і O&O Shutup видаляться після того, як робота буде виконана.
$configText = @"
P001	+	# Disable sharing of handwriting data (Category: Privacy)
P002	+	# Disable sharing of handwriting error reports (Category: Privacy)
P003	+	# Disable Inventory Collector (Category: Privacy)
P004	-	# Disable camera in logon screen (Category: Privacy)
P005	+	# Disable and reset Advertising ID and info for the machine (Category: Privacy)
P006	+	# Disable and reset Advertising ID and info (Category: Privacy)
P008	+	# Disable transmission of typing information (Category: Privacy)
P026	+	# Disable advertisements via Bluetooth (Category: Privacy)
P027	+	# Disable the Windows Customer Experience Improvement Program (Category: Privacy)
P028	+	# Disable backup of text messages into the cloud (Category: Privacy)
P064	+	# Disable suggestions in the timeline (Category: Privacy)
P065	+	# Disable suggestions in Start (Category: Privacy)
P066	+	# Disable tips, tricks, and suggestions when using Windows (Category: Privacy)
P067	+	# Disable showing suggested content in the Settings app (Category: Privacy)
P070	+	# Disable the possibility of suggesting to finish the setup of the device (Category: Privacy)
P069	+	# Disable Windows Error Reporting (Category: Privacy)
P009	-	# Disable biometrical features (Category: Privacy)
P010	-	# Disable app notifications (Category: Privacy)
P015	-	# Disable access to local language for browsers (Category: Privacy)
P068	-	# Disable text suggestions when typing on the software keyboard (Category: Privacy)
P016	-	# Disable sending URLs from apps to Windows Store (Category: Privacy)
A001	+	# Disable recordings of user activity (Category: Activity History and Clipboard)
A002	+	# Disable storing users' activity history (Category: Activity History and Clipboard)
A003	+	# Disable the submission of user activities to Microsoft (Category: Activity History and Clipboard)
A004	+	# Disable storage of clipboard history for whole machine (Category: Activity History and Clipboard)
A006	+	# Disable storage of clipboard history (Category: Activity History and Clipboard)
A005	+	# Disable the transfer of the clipboard to other devices via the cloud (Category: Activity History and Clipboard)
P007	+	# Disable app access to user account information (Category: App Privacy)
P036	+	# Disable app access to user account information (Category: App Privacy)
P025	+	# Disable Windows tracking of app starts (Category: App Privacy)
P033	+	# Disable app access to diagnostics information (Category: App Privacy)
P023	+	# Disable app access to diagnostics information (Category: App Privacy)
P056	-	# Disable app access to device location (Category: App Privacy)
P057	-	# Disable app access to device location (Category: App Privacy)
P012	-	# Disable app access to camera (Category: App Privacy)
P034	-	# Disable app access to camera (Category: App Privacy)
P013	-	# Disable app access to microphone (Category: App Privacy)
P035	-	# Disable app access to microphone (Category: App Privacy)
P062	-	# Disable app access to use voice activation (Category: App Privacy)
P063	-	# Disable app access to use voice activation when device is locked (Category: App Privacy)
P081	-	# Disable the standard app for the headset button (Category: App Privacy)
P047	-	# Disable app access to notifications (Category: App Privacy)
P019	-	# Disable app access to notifications (Category: App Privacy)
P048	-	# Disable app access to motion (Category: App Privacy)
P049	-	# Disable app access to movements (Category: App Privacy)
P020	-	# Disable app access to contacts (Category: App Privacy)
P037	-	# Disable app access to contacts (Category: App Privacy)
P011	-	# Disable app access to calendar (Category: App Privacy)
P038	-	# Disable app access to calendar (Category: App Privacy)
P050	-	# Disable app access to phone calls (Category: App Privacy)
P051	-	# Disable app access to phone calls (Category: App Privacy)
P018	-	# Disable app access to call history (Category: App Privacy)
P039	-	# Disable app access to call history (Category: App Privacy)
P021	-	# Disable app access to email (Category: App Privacy)
P040	-	# Disable app access to email (Category: App Privacy)
P022	-	# Disable app access to tasks (Category: App Privacy)
P041	-	# Disable app access to tasks (Category: App Privacy)
P014	-	# Disable app access to messages (Category: App Privacy)
P042	-	# Disable app access to messages (Category: App Privacy)
P052	-	# Disable app access to radios (Category: App Privacy)
P053	-	# Disable app access to radios (Category: App Privacy)
P054	-	# Disable app access to unpaired devices (Category: App Privacy)
P055	-	# Disable app access to unpaired devices (Category: App Privacy)
P029	-	# Disable app access to documents (Category: App Privacy)
P043	-	# Disable app access to documents (Category: App Privacy)
P030	-	# Disable app access to images (Category: App Privacy)
P044	-	# Disable app access to images (Category: App Privacy)
P031	-	# Disable app access to videos (Category: App Privacy)
P045	-	# Disable app access to videos (Category: App Privacy)
P032	-	# Disable app access to the file system (Category: App Privacy)
P046	-	# Disable app access to the file system (Category: App Privacy)
P058	-	# Disable app access to unpaired devices (Category: App Privacy)
P059	-	# Disable app access to unpaired devices (Category: App Privacy)
P060	-	# Disable app access to eye tracking (Category: App Privacy)
P061	-	# Disable app access to eye tracking (Category: App Privacy)
P071	-	# Disable the ability for apps to take screenshots (Category: App Privacy)
P072	-	# Disable the ability for apps to take screenshots (Category: App Privacy)
P073	-	# Disable the ability for desktop apps to take screenshots (Category: App Privacy)
P074	-	# Disable the ability for apps to take screenshots without borders (Category: App Privacy)
P075	-	# Disable the ability for apps to take screenshots without borders (Category: App Privacy)
P076	-	# Disable the ability for desktop apps to take screenshots without margins (Category: App Privacy)
P077	-	# Disable app access to music libraries (Category: App Privacy)
P078	-	# Disable app access to music libraries (Category: App Privacy)
P079	-	# Disable app access to downloads folder (Category: App Privacy)
P080	-	# Disable app access to downloads folder (Category: App Privacy)
P024	-	# Prohibit apps from running in the background (Category: App Privacy)
S001	-	# Disable password reveal button (Category: Security)
S002	+	# Disable user steps recorder (Category: Security)
S003	+	# Disable telemetry (Category: Security)
S008	-	# Disable Internet access of Windows Media Digital Rights Management (DRM) (Category: Security)
E101	+	# Disable tracking in the web (Category: Microsoft Edge (new version based on Chromium))
E201	+	# Disable tracking in the web (Category: Microsoft Edge (new version based on Chromium))
E115	+	# Disable check for saved payment methods by sites (Category: Microsoft Edge (new version based on Chromium))
E215	+	# Disable check for saved payment methods by sites (Category: Microsoft Edge (new version based on Chromium))
E118	+	# Disable personalizing advertising, search, news and other services (Category: Microsoft Edge (new version based on Chromium))
E218	+	# Disable personalizing advertising, search, news and other services (Category: Microsoft Edge (new version based on Chromium))
E107	+	# Disable automatic completion of web addresses in address bar (Category: Microsoft Edge (new version based on Chromium))
E207	+	# Disable automatic completion of web addresses in address bar (Category: Microsoft Edge (new version based on Chromium))
E111	+	# Disable user feedback in toolbar (Category: Microsoft Edge (new version based on Chromium))
E211	+	# Disable user feedback in toolbar (Category: Microsoft Edge (new version based on Chromium))
E112	+	# Disable storing and autocompleting of credit card data on websites (Category: Microsoft Edge (new version based on Chromium))
E212	+	# Disable storing and autocompleting of credit card data on websites (Category: Microsoft Edge (new version based on Chromium))
E109	+	# Disable form suggestions (Category: Microsoft Edge (new version based on Chromium))
E209	+	# Disable form suggestions (Category: Microsoft Edge (new version based on Chromium))
E121	+	# Disable suggestions from local providers (Category: Microsoft Edge (new version based on Chromium))
E221	-	# Disable suggestions from local providers (Category: Microsoft Edge (new version based on Chromium))
E103	+	# Disable search and website suggestions (Category: Microsoft Edge (new version based on Chromium))
E203	-	# Disable search and website suggestions (Category: Microsoft Edge (new version based on Chromium))
E123	+	# Disable shopping assistant in Microsoft Edge (Category: Microsoft Edge (new version based on Chromium))
E223	+	# Disable shopping assistant in Microsoft Edge (Category: Microsoft Edge (new version based on Chromium))
E124	-	# Disable Edge bar (Category: Microsoft Edge (new version based on Chromium))
E224	+	# Disable Edge bar (Category: Microsoft Edge (new version based on Chromium))
E128	-	# Disable Sidebar in Microsoft Edge (Category: Microsoft Edge (new version based on Chromium))
E228	-	# Disable Sidebar in Microsoft Edge (Category: Microsoft Edge (new version based on Chromium))
E119	-	# Disable use of web service to resolve navigation errors (Category: Microsoft Edge (new version based on Chromium))
E219	-	# Disable use of web service to resolve navigation errors (Category: Microsoft Edge (new version based on Chromium))
E120	-	# Disable suggestion of similar sites when website cannot be found (Category: Microsoft Edge (new version based on Chromium))
E220	-	# Disable suggestion of similar sites when website cannot be found (Category: Microsoft Edge (new version based on Chromium))
E122	-	# Disable preload of pages for faster browsing and searching (Category: Microsoft Edge (new version based on Chromium))
E222	-	# Disable preload of pages for faster browsing and searching (Category: Microsoft Edge (new version based on Chromium))
E125	-	# Disable saving passwords for websites (Category: Microsoft Edge (new version based on Chromium))
E225	-	# Disable saving passwords for websites (Category: Microsoft Edge (new version based on Chromium))
E126	-	# Disable site safety services for more information about a visited website (Category: Microsoft Edge (new version based on Chromium))
E226	-	# Disable site safety services for more information about a visited website (Category: Microsoft Edge (new version based on Chromium))
E106	-	# Disable SmartScreen Filter (Category: Microsoft Edge (new version based on Chromium))
E206	-	# Disable SmartScreen Filter (Category: Microsoft Edge (new version based on Chromium))
E127	-	# Disable typosquatting checker for site addresses (Category: Microsoft Edge (new version based on Chromium))
E227	-	# Disable typosquatting checker for site addresses (Category: Microsoft Edge (new version based on Chromium))
E001	+	# Disable tracking in the web (Category: Microsoft Edge (legacy version))
E002	+	# Disable page prediction (Category: Microsoft Edge (legacy version))
E003	+	# Disable search and website suggestions (Category: Microsoft Edge (legacy version))
E008	+	# Disable Cortana in Microsoft Edge (Category: Microsoft Edge (legacy version))
E007	+	# Disable automatic completion of web addresses in address bar (Category: Microsoft Edge (legacy version))
E010	+	# Disable showing search history (Category: Microsoft Edge (legacy version))
E011	+	# Disable user feedback in toolbar (Category: Microsoft Edge (legacy version))
E012	+	# Disable storing and autocompleting of credit card data on websites (Category: Microsoft Edge (legacy version))
E009	-	# Disable form suggestions (Category: Microsoft Edge (legacy version))
E004	-	# Disable sites saving protected media licenses on my device (Category: Microsoft Edge (legacy version))
E005	-	# Do not optimize web search results on the task bar for screen reader (Category: Microsoft Edge (legacy version))
E013	+	# Disable Microsoft Edge launch in the background (Category: Microsoft Edge (legacy version))
E014	+	# Disable loading the start and new tab pages in the background (Category: Microsoft Edge (legacy version))
E006	-	# Disable SmartScreen Filter (Category: Microsoft Edge (legacy version))
F002	+	# Disable telemetry for Microsoft Office (Category: Microsoft Office)
F014	+	# Disable diagnostic data submission (Category: Microsoft Office)
F015	+	# Disable participation in the Customer Experience Improvement Program (Category: Microsoft Office)
F016	+	# Disable the display of LinkedIn information (Category: Microsoft Office)
F001	+	# Disable inline text prediction in mails (Category: Microsoft Office)
F003	+	# Disable logging for Microsoft Office Telemetry Agent (Category: Microsoft Office)
F004	+	# Disable upload of data for Microsoft Office Telemetry Agent (Category: Microsoft Office)
F005	+	# Obfuscate file names when uploading telemetry data (Category: Microsoft Office)
F007	+	# Disable Microsoft Office surveys (Category: Microsoft Office)
F008	+	# Disable feedback to Microsoft (Category: Microsoft Office)
F009	+	# Disable Microsoft's feedback tracking (Category: Microsoft Office)
F006	-	# Disable automatic receipt of updates (Category: Microsoft Office)
F010	-	# Disable connected experiences in Office (Category: Microsoft Office)
F011	-	# Disable connected experiences with content analytics (Category: Microsoft Office)
F012	-	# Disable online content downloading for connected experiences (Category: Microsoft Office)
F013	-	# Disable optional connected experiences in Office (Category: Microsoft Office)
Y001	-	# Disable synchronization of all settings (Category: Synchronization of Windows Settings)
Y002	-	# Disable synchronization of design settings (Category: Synchronization of Windows Settings)
Y003	-	# Disable synchronization of browser settings (Category: Synchronization of Windows Settings)
Y004	-	# Disable synchronization of credentials (passwords) (Category: Synchronization of Windows Settings)
Y005	-	# Disable synchronization of language settings (Category: Synchronization of Windows Settings)
Y006	-	# Disable synchronization of accessibility settings (Category: Synchronization of Windows Settings)
Y007	-	# Disable synchronization of advanced Windows settings (Category: Synchronization of Windows Settings)
C012	+	# Disable and reset Cortana (Category: Cortana (Personal Assistant))
C002	+	# Disable Input Personalization (Category: Cortana (Personal Assistant))
C013	+	# Disable online speech recognition (Category: Cortana (Personal Assistant))
C007	+	# Cortana and search are disallowed to use location (Category: Cortana (Personal Assistant))
C008	+	# Disable web search from Windows Desktop Search (Category: Cortana (Personal Assistant))
C009	+	# Disable display web results in Search (Category: Cortana (Personal Assistant))
C010	+	# Disable download and updates of speech recognition and speech synthesis models (Category: Cortana (Personal Assistant))
C011	+	# Disable cloud search (Category: Cortana (Personal Assistant))
C014	+	# Disable Cortana above lock screen (Category: Cortana (Personal Assistant))
C015	+	# Disable the search highlights in the taskbar (Category: Cortana (Personal Assistant))
C101	+	# Disable the Windows Copilot (Category: Windows Copilot)
C201	+	# Disable the Windows Copilot (Category: Windows Copilot)
C102	+	# Disable the Copilot button from the taskbar (Category: Windows Copilot)
C103	+	# Disable Windows Copilot+ Recall (Category: Windows Copilot)
C203	+	# Disable Windows Copilot+ Recall (Category: Windows Copilot)
L001	+	# Disable functionality to locate the system (Category: Location Services)
L003	+	# Disable scripting functionality to locate the system (Category: Location Services)
L004	-	# Disable sensors for locating the system and its orientation (Category: Location Services)
L005	-	# Disable Windows Geolocation Service (Category: Location Services)
U001	+	# Disable application telemetry (Category: User Behavior)
U004	+	# Disable diagnostic data from customizing user experiences for whole machine (Category: User Behavior)
U005	+	# Disable the use of diagnostic data for a tailor-made user experience (Category: User Behavior)
U006	-	# Disable diagnostic log collection (Category: User Behavior)
U007	-	# Disable downloading of OneSettings configuration settings (Category: User Behavior)
W001	+	# Disable Windows Update via peer-to-peer (Category: Windows Update)
W011	+	# Disable updates to the speech recognition and speech synthesis modules. (Category: Windows Update)
W004	-	# Activate deferring of upgrades (Category: Windows Update)
W005	-	# Disable automatic downloading manufacturers' apps and icons for devices (Category: Windows Update)
W010	-	# Disable automatic driver updates through Windows Update (Category: Windows Update)
W009	-	# Disable automatic app updates through Windows Update (Category: Windows Update)
P017	-	# Disable Windows dynamic configuration and update rollouts (Category: Windows Update)
W006	-	# Disable automatic Windows Updates (Category: Windows Update)
W008	-	# Disable Windows Updates for other products (e.g. Microsoft Office) (Category: Windows Update)
M006	+	# Disable occassionally showing app suggestions in Start menu (Category: Windows Explorer)
M011	+	# Do not show recently opened items in Jump Lists on "Start" or the taskbar (Category: Windows Explorer)
M010	+	# Disable ads in Windows Explorer/OneDrive (Category: Windows Explorer)
O003	-	# Disable OneDrive access to network before login (Category: Windows Explorer)
O001	-	# Disable Microsoft OneDrive (Category: Windows Explorer)
S012	+	# Disable Microsoft SpyNet membership (Category: Microsoft Defender and Microsoft SpyNet)
S013	+	# Disable submitting data samples to Microsoft (Category: Microsoft Defender and Microsoft SpyNet)
S014	+	# Disable reporting of malware infection information (Category: Microsoft Defender and Microsoft SpyNet)
K001	+	# Disable Windows Spotlight (Category: Lock Screen)
K002	+	# Disable fun facts, tips, tricks, and more on your lock screen (Category: Lock Screen)
K005	+	# Disable notifications on lock screen (Category: Lock Screen)
M025	+	# Disable search with AI in search box (Category: Search)
M003	+	# Disable extension of Windows search with Bing (Category: Search)
M015	+	# Disable People icon in the taskbar (Category: Taskbar)
M016	+	# Disable search box in task bar (Category: Taskbar)
M017	+	# Disable "Meet now" in the task bar (Category: Taskbar)
M018	+	# Disable "Meet now" in the task bar (Category: Taskbar)
M019	+	# Disable news and interests in the task bar (Category: Taskbar)
M020	+	# Disable news and interests in the task bar (Category: Taskbar)
M021	+	# Disable widgets in Windows Explorer (Category: Taskbar)
M022	+	# Disable feedback reminders (Category: Miscellaneous)
M001	+	# Disable feedback reminders (Category: Miscellaneous)
M004	+	# Disable automatic installation of recommended Windows Store Apps (Category: Miscellaneous)
M005	+	# Disable tips, tricks, and suggestions while using Windows (Category: Miscellaneous)
M024	-	# Disable Windows Media Player Diagnostics (Category: Miscellaneous)
M026	+	# Disable remote assistance connections to this computer (Category: Miscellaneous)
M027	+	# Disable remote connections to this computer (Category: Miscellaneous)
M012	-	# Disable Key Management Service Online Activation (Category: Miscellaneous)
M013	+	# Disable automatic download and update of map data (Category: Miscellaneous)
M014	+	# Disable unsolicited network traffic on the offline maps settings page (Category: Miscellaneous)
N001	-	# Disable Network Connectivity Status Indicator (Category: Miscellaneous)
"@

# Зберегти до файлу конфігурації увесь текст вище
$configFilePath = "C:\Support\Scripts\ooshutup10.cfg"

# Створення директорії, якщо вона не існує
If (!(Test-Path "C:\Support\Scripts")) {
    New-Item -Path "C:\Support\Scripts" -ItemType Directory | Out-Null
}

# Збереження тексту конфігурації у файл
$configText | Out-File -FilePath $configFilePath -Encoding UTF8
#Завантаження та запуск O&O Shutup
    Invoke-WebRequest -Uri "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -outFile "C:\Support\Scripts\OOSU10.exe"
    cd C:\Support\Scripts
    ./OOSU10.exe ooshutup10.cfg /quiet

    Write-Host  -ForegroundColor DarkMagenta "Вимикаємо телеметрію в планувальнику"
    $ResultText.text += "`r`n" +"Вимикаємо телеметрію..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
	#Вимикаємо WiFi Sence. Це не дасть нам змогу автоматично шарити інформацію про наш ПК в мережі, щоб інші користувачі бачили нас для обміну файлами, проте сильно покращить безпеку системи.
    Write-Host  -ForegroundColor DarkMagenta "Вимикаємо Wi-Fi Sense..."
    If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
    Write-Host  -ForegroundColor DarkMagenta "Вимикаємо пропозиції застосунків..."
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1
    Write-Host  -ForegroundColor DarkMagenta "Disabling Activity History..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0
    
	# Цю частину лишаю закоментованою (значить ця частина скрипта не працюватиме), бо вона ВИмикає відслідковування локації ПК. Дуже потрібна штука в мапах тощо. Також закоментував скрипт, що вимикає звітування про помилки Windows. Код залишаю, якщо комусь треба це вимикати
	<#
    Write-Host  -ForegroundColor DarkMagenta "Вимикаємо відстежування локації.."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
    Write-Host  -ForegroundColor DarkMagenta "Вимикаємо автоматичні оновлення мап..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
    Write-Host  -ForegroundColor DarkMagenta "Disabling Feedback..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
    Write-Host  -ForegroundColor DarkMagenta "Disabling Tailored Experiences..."
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1
    Write-Host  -ForegroundColor DarkMagenta "Disabling Advertising ID..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1
    Write-Host  -ForegroundColor DarkMagenta "Disabling Error reporting..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
	#>
	
    Write-Host  -ForegroundColor DarkMagenta "Дозволяємо Windows Update P2P тільки всередині локальної мережі..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
    Write-Host  -ForegroundColor DarkMagenta "Зупиняємо та вимикаємо Diagnostics Tracking Service..."
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled
#WAP Push Service використовується в різних контекстах, наприклад:
    #Оновлення програмного забезпечення: Відправка посилань на завантаження оновлень для мобільних додатків або операційної системи.
    #Маркетингові кампанії: Відправка посилань на спеціальні пропозиції або нові продукти.
    #Банківські та фінансові послуги: Відправка повідомлень про транзакції або важливу інформацію про рахунок.
    #Конфігурація пристрою: Відправка налаштувань для служб, таких як MMS або мобільний інтернет.
#За допомогою повідомлень через WAP_Pushing можна отримати фішінгові повідомлення, або повідомлення, що завантажують шкідливий код. Проте їх вимкнення не дасть вам змогу отримувати повідомлення про важливі оновлення тощо. Нехай працює собі, якщо ви не людина, що клікає на всі повідомлення про спортлото.
<#
    Write-Host  -ForegroundColor DarkMagenta "Зупиняємо та вимикаємо WAP Push Service..."
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled
	#>
#Починаючи з Windows 10 версії 1803, Microsoft припинила підтримку функції домашніх груп.Мати цей сервіс необхідно лише якщо обмінюєтесь файлами чи принтерами всередині мережі зі старими версіями ОС Windows.
    Write-Host  -ForegroundColor DarkMagenta "Зупиняємо та вимикаємо сервіс домашніх груп"
    Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
    Set-Service "HomeGroupListener" -StartupType Disabled
    Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
    Set-Service "HomeGroupProvider" -StartupType Disabled
#Remote Assistance у Windows є потужним інструментом для отримання або надання допомоги на відстані. Це особливо корисно в корпоративному середовищі, де технічна підтримка може швидко і ефективно вирішувати проблеми користувачів. Для домашнього користування, користувачі надають перевагу стороннім застосункам, таким, як AnyDesk.Тож можна видалити.
    Write-Host  -ForegroundColor DarkMagenta "Вимикаємо Remote Assistance..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

#Гібернація — це енергозберігаючий стан, який дозволяє зберігати стан комп'ютера на жорсткому диску, а потім повністю вимикати систему. На стаціонарному ПК не бачу в цьому ніякого сенсу. Для ноутбуків же краще видалити (або занотувати) рядки, що вимикають гібернацію, бо там ця функція стане у пригоді.
    Write-Host  -ForegroundColor DarkMagenta "Вимкнення Hibernation..."
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -Type Dword -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0

# Налаштування диспетчера завдань
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
# Показ операцій з файлами
Write-Host -ForegroundColor DarkMagenta "Показуємо деталі операцій з файлами..."
If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
    New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
}
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1

# Приховування кнопки Task View
Write-Host -ForegroundColor DarkMagenta "Приховуємо кнопку TaskView..."
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0
#Приховуємо значок Люди з панелі завдань
    Write-Host  -ForegroundColor DarkMagenta "Приховуємо значок Люди якщо він є..."
    If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0
#Увімкнення Num Lock при запуску — це зручна конфігурація для багатьох користувачів, яка дозволяє уникнути додаткових дій та забезпечує комфортне використання числової клавіатури одразу після завантаження системи. Це особливо корисно для тих, хто часто працює з числовими даними або паролями, що містять цифри.
    Write-Host  -ForegroundColor DarkMagenta "Вмикаємо NumLock при запуску..."
    If (!(Test-Path "HKU:")) {
        New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
    }
    Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
    Add-Type -AssemblyName System.Windows.Forms
    If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
        $wsh = New-Object -ComObject WScript.Shell
        $wsh.SendKeys('{NUMLOCK}')
    }
    Write-Host  -ForegroundColor DarkMagenta "Changing default Explorer view to This PC..."
    $ResultText.text += "`r`n" +"Quality of Life Tweaks"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

    Write-Host  -ForegroundColor DarkMagenta "Hiding 3D Objects icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

	#Зазвичай параметр IRPStackSize встановлюється для збільшення стеку IRP в системі, що дозволяє краще управляти мережевими операціями і зменшити можливість виникнення помилок, пов'язаних з перевищенням розміру стеку. Це особливо важливо для великих мережевих середовищ або в умовах високого навантаження на сервер.
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "IRPStackSize" -Type DWord -Value 20

#Є відчуття ностальгії? Можемо встановити Windows Media Player
    <# 
    Write-Host  -ForegroundColor DarkMagenta "Встановлюю класичний Windows Media Player..."
	Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null #>

    Write-Host  -ForegroundColor DarkMagenta "Вимкнути новини та інтереси"
    $ResultText.text += "`r`n" +"Disabling Extra Junk"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
    # Видаляємо "Новини та Інтереси" з панелі завдань
    Set-ItemProperty -Path  "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2

    # Видаляємо кнопку "Створити зутріч" з панелі завдань якщо вона є

    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Force | Out-Null
    }

Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Type DWord -Value 1

#Autologger - файл у який пишеться дуже багато телеметрії Microsoft і потім відправляється на опрацювання. Якщо ви також не хочете, щоб про вас збирали та відправляли якісь дані, то вимикаємо це все діло, та забороняємо системі створювати нові файли в тій теці на відправку.
    Write-Host  -ForegroundColor DarkMagenta "Видаляємо файл AutoLogger та забороняємо доступ до його директорії..."
    $autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
    If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
        Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
    }
    icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

    Write-Host  -ForegroundColor DarkMagenta "Зупиняємо та вимикаємо Diagnostics Tracking Service..."
    Stop-Service "DiagTrack"
    Set-Service "DiagTrack" -StartupType Disabled
#дуже важливо для безпеки системи, щоб користувач бачив, що ніхто не замаскував небезпечний скрипт під інший файл. Якщо ви бачите розширення файлів, такий фокус з вами не пройде
    Write-Host -ForegroundColor DarkMagenta "Вмикаємо показ відомих файлових розширень..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

    # Перемикаємо сервіси у ручний режим. Якщо система матиме запит до сервіса в ручному режимі, його буде запущено. Навідміну від скриптів, що вимикають сервіси назавжди. Тоді буде помилка при запиті.
	#Служби, що мають # на початку не вимикається, а просто є. Якщо, наприклад, ти захочеш вимкнути ці служби у себе.
	#вимикаю тільки ті служби, що негативно впливають на безпеку. Більшість сервісів ніяк не впливають на продуктивність, хоча їх вимкнення може додати проблем.

    $services = @(
    "diagnosticshub.standardcollector.service"     # Microsoft (R) Diagnostics Hub Standard Collector Service - служба в операційній системі Windows, яка відповідає за збирання та обробку діагностичних даних.Нічого корисного для нас не робить. 
	
    "DiagTrack"                                    # (Diagnostic Tracking Service) також відомий як Connected User Experiences and Telemetry Service — це служба Windows, яка збирає та передає діагностичні дані до Microsoft. Покращує систему відправлянням даних, тільки ось з часом система чомусь не покращується.
	
    #"DPS"										   #(Diagnostic Policy Service) у Windows відповідає за виявлення та усунення проблем в операційній системі. Та сама, що намагається виправити проблему, але ніколи її не виправляє. Актор без оскара.
	
    #"dmwappushservice"                            # (Device Management Wireless Application Protocol (WAP) Push message Routing Service) — це служба в операційній системі Windows, яка відповідає за обробку WAP Push повідомлень.Потрібна для обробки повідомлень автоматичних налаштувань інтернету, коли підключаєш модем. Але її вимкнення може понести додаткові проблеми. Нехай собі працює.
	
    #"lfsvc"                                       # Geolocation Service. Вимикати геолокацію - це не зручно. Але якщо прямо сильно шифруєшся, то вимикай. Але по IP все одно зможуть вичислити, якщо що.
	
    "MapsBroker"                                   # Downloaded Maps Manager. Загалом потрібна тільки якщо використовуєш застосунки із завантаженими мапами на систему, щоб накладати на них поточну геолокацію. Для домашнього ПК можна вимкнути.
    #"NetTcpPortSharing"                           # Net.Tcp Port Sharing Service є важливим компонентом для забезпечення спільного використання TCP-портів декількома службами в операційній системі Windows. Він сприяє ефективному використанню мережевих ресурсів і інтеграції додатків, що використовують Windows Communication Foundation. Вимикаючи збільшимо безпеку системи, бо для кожного з'єднання буде відкриватись окремий порт. Проте збільшимо навантаження на мережу.
	
    "RemoteAccess"                                 # Routing and Remote Access. Віддалений доступ до ПК стандартними засобами Windows. Люди використовують для цього TeamViewer чи AnyDesk. RDP з'єднання після вимкнення продовжить чудово працювати.
	
    "RemoteRegistry"                               # Remote Registry. Служба віддаленого реєстру. Для домашнього ПК не має сенсу.
	
    #"SharedAccess"                                # Internet Connection Sharing (ICS) Служба SharedAccess в операційній системі Windows відповідає за управління мережевими правилами та функціями обмеження доступу через мережевий міст (Network Bridge). Працює у парі з Файєрволом. І нехай працює.
	
    #"TrkWks"                                       # Distributed Link Tracking — це служба в операційній системі Windows, яка відповідає за відстеження посилань на файлові об'єкти в розподілених обчислювальних середовищах.Вона спрощує доступ до розподілених файлових ресурсів і забезпечує синхронізацію інформації про посилання між різними комп'ютерами у мережі.
	
    #"WbioSrvc"                                     # Windows Biometric Service - служба, що керує засобами біометрії. Якщо у тебе на ПК є вхід по відбитку пальця чи камері Windows Hello, службу треба лишити. 
	
    #"WlanSvc"                                      # WLAN AutoConfig. Автоматичне налаштування мережі WiFi. Вимкнення негативно впливає на стабільність підключення по WiFi. Якщо ж у тебе дротове з'єднання з інтернетом, то можна вимкнути.
	
    "WMPNetworkSvc"                                # Windows Media Player Network Sharing Service - це служба в операційній системі Windows, яка відповідає за мережеву спільнодію мультимедійних файлів і пристроїв через Windows Media Player.Якщо у тебе немає WMP, то і служба не потрібна.
	
    #"wscsvc"                                      # Windows Security Center Service - служба, що моніторить стан усіх безпекових застосунків та сповіщая, якщо щось не так.
	
    "WSearch"                                      # Windows Search. Служба, що відповідає за індексування та пошук в системі Windows. Працює хиленько, можна вимкнути та використовувати пошуковик по типу Everything
	
	#Служби Xbox необхідні для роботи ігор від Microsoft та деяких інших ігор. Якщо не граєте в ігри, то можна вимкнути наступні 5 сервісів.
    #"XblAuthManager"                               # Xbox Live Auth Manager
    #"XblGameSave"                                  # Xbox Live Game Save Service
    #"XboxNetApiSvc"                                # Xbox Live Networking Service
    #"XboxGipSvc"                                   # Xbox Accessory Management Service
	#"CaptureService_48486de"                       #Служба, що потрібна для роботи Windows.Graphics.Capture API, який є частиною Xbox GameBar.  
	
	"BcastDVRUserService_48486de"					#використовується для забезпечення функцій трансляції та запису ігрового процесу. Це корисно для геймерів, які хочуть транслювати свої ігри на платформах для стримінгу або записувати їх для подальшого перегляду і редагування. Є сенс вимикати, якщо користуєтесь сторонніми засобами.
	
    #"ndu"                                          # Windows Network Data Usage Monitor є важливим компонентом для моніторингу та управління мережевим трафіком в операційній системі Windows. Він дозволяє користувачам і адміністраторам контролювати, як програми використовують мережу і забезпечувати ефективне використання доступного інтернет-трафіку. Якщо слідкувати за тим скільки витрачено трафіку у мережі не потрібно, сервіс можна вимкнути.
	
    #"WerSvc"                                      #Відповідає за звітування про помилки. Ось це, я вважаю, можна і залишити. Про помилки в системі Microsoft варто знати.
	
    #"Spooler"                                      #Вимикає всі твої принтери. Якщо принтерів нема й не буде, то службу принтерів можна вимикати.
	
    "Fax"                                          #Вимкнути факс. Якщо ти навіть не знаєш, що таке факс, то навряд тобі ця служба стане у пригоді. Можна точно вимикати.
	
    "fhsvc"                                        #Вимкнути службу історії факсів. Давно не зустрічав факсів. Можна вимикати разом із попередньою службою.
	
    #"gupdate"                                      #вимкнути оновлення всіх застосунків від Google (не рекомендується, якщо активно користуєшся сервісами від Google)
	
    #"gupdatem"                                     #Вимкнути ще один сервіс оновлення Google
	
    #"stisvc"                                       #Вимикає Windows Image Acquisition (WIA), це сервіс, що впливає на взаємодію зі сканером чи камерою (будь-яким пристроєм), що передають зображення у Windows напряму. Якщо таких пристроїв немає, сервіс можна вимкнути.
	
    #"AJRouter"                                     #Ця служба важлива для роботи пристроїв, що використовують AllJoyn для зв'язку та взаємодії. Якщо у вас є пристрої IoT, які використовують цей протокол, робота служби AJRouter дозволить їм коректно взаємодіяти один з одним.У іншому випадку можна вимикати.
	
    #"MSDTC"                                       # Distributed Transaction Coordinator - не рекомендую вимикати службу. Хоч вона здебільшого створювалася для координації розподілених транзакцій на серверних системах, проте також допомагає зберігати файли цілісними при копіюванні чи переміщенні.
	
    #"WpcMonSvc"                                    #Служба батьківського контролю на ПК. Якщо не використовуєте батьківський контроль для дітей, то і служба вам не потрібна.
	
    #"PhoneSvc"                                     #Вимикаючи Phone Service ви вимкнете можливості телефонії та пересилання SMS на комп'ютері за допомогою підключених пристоїв (саме через мобільні мережі). Якщо ви не телефонуєте з комп'ютера через мобільні мережі, службу можна вимкнути.
	
    #"PrintNotify"                                  #служба Windows, яка відповідає за оповіщення користувачів про стан друку. Вона забезпечує функціональність повідомлень про друк, таких як спливаючі повідомлення про завдання друку, стан друку, помилки тощо. Якщо не користуєшся принтером, то і службу можна вимкнути.
	
    #"PcaSvc"                                       #служба, яка допомагає користувачам запускати старі програми, що можуть мати проблеми з сумісністю на новіших версіях операційної системи Windows. Якщо не користуєшся застарілими програмами, службу можна вимкнути.
	
    #"WPDBusEnum"                                   #служба, яка керує підключенням і взаємодією з портативними пристроями, такими як цифрові камери, медіаплеєри, смартфони та інші пристрої, що використовують протокол MTP (Media Transfer Protocol) або PTP (Picture Transfer Protocol). Якщо підключаєш до ПК смартфон чи фотоапарат, служба має працювати. 
	
    #"LicenseManager"                               #вимкнення LicenseManager зламає роботу магазина Windows. Якщо магазин Windows тебе не цікавить - можна вимикати.
	
    #"seclogon"                                     #Вимикає інші облікові записи та повторний вхід. Якщо плануєш мати лише один обліковий запис на ПК, службу можна вимкнути.
	
    #"SysMain"                                      #Найдивніший вчинок, який можна зробити - це вимкнути Sysmain, він же SuperFetch, що кешує файли та застосунки для прискорення системи. Єдиний сценарій, де можна вимкнути, це коли 4 та менше Гб ОЗП та система стоїть на HDD. 
	
    #"lmhosts"                                      #Вимикаємо помічника для застарілої технології TCP/IP NetBIOS. Якщо у вашій мережі немає пристроїв на старих версіях ОС (нижче Windows 10), то службу можна і треба вимикати заради безпеки. 
	
    #"wisvc"                                        #Вимикає Windows Insider program. Програма тестування нових версій Windows до їх релізу не буде доступна. 
	
    #"FontCache"                                    #(Windows Font Cache Service)є важливою частиною системи Windows для забезпечення ефективності використання шрифтів у різноманітних програмах і інтерфейсі системи. Вона сприяє збереженню ресурсів комп'ютера та покращує загальну продуктивність шляхом оптимізації роботи з шрифтами.Нуль сенсу вимикати.
	
    "RetailDemo"                                   #функція Windows, яка надає спеціальний режим демонстрації для використання в роздрібних магазинах. У цьому режимі комп'ютер налаштовується таким чином, щоб демонструвати функції та можливості операційної системи Windows і встановлених застосунків, часто в циклічному режимі, щоб залучити потенційних покупців.Так як комп'ютер вже куплений, можна вимикати.
	
    #"ALG"                                          # Вимикає Application Layer Gateway Service що створена для забезпечення коректної роботи мережевих застосунків, що використовують специфічні протоколи, особливо в середовищах з NAT і брандмауерами. Вона допомагає обходити обмеження мережевих трансляторів і забезпечує належний рівень безпеки мережевого трафіку.Вимикати не рекомендується.

    #"BFE"                                         #Base Filtering Engine (BFE) (сервіс, що керує файєрволом та Internet Protocol Security). Вимикати не рекомендується.
	
    #"BrokerInfrastructure"                         #служба Windows infrastructure допомагає оптимізувати використання ресурсів та підтримувати стабільність системи, що є ключовим для багатозадачної роботи операційної системи.Не вимикати.
	
    "SCardSvr"                                      #Служба, що відповідає за авторизацію через Windows smart card. Не впевнений, що є великий шанс зустріти застосунки, що використовують SmartCard. Можна вимкнути.
	
    "EntAppSvc"                                     #Служба для корпоративного керування застосунками. На домашньому ПК їй робити нічого.
	
    #"BthAvctpSvc"                                   #служба, яка забезпечує підтримку аудіо- та відеопрофілів Bluetooth, зокрема, профілів Advanced Audio Distribution Profile (A2DP) і Audio/Video Remote Control Profile (AVRCP). Якщо використовуєте Bluetooth-пристрої для аудіо, вимикати не потрібно.
	
    #"FrameServer"                                   #служба Windows Camera Frame Server дає змогу багатьом застосункам використовувати камеру одночасно. Якщо вимкнути службу, то при запиті від іншого застосунка писатиме, що камера зайнята.
	
    #"BthAvctpSvc"                                   #AVCTP сервіс відповідає за підтримку аудіо- і відеопрофілів через Bluetooth, зокрема профілів, які використовують Audio/Video Control Transport Protocol (AVCTP).Якщо користуєтесь Bluetooth аудіо вимикати не треба.
	
    "BDESVC"                                        #Вимкнути bitlocker. Це безпековий засіб для шифрування даних на ПК. Робить неможливим доступ до даних при викраденні ком'ютера чи диска. Можна вимикати тільки якщо до цього нічого ним не шифрували.Якщо працює, трохи знижує швидкодію. Має сенс вимкнути, якщо вам не потрібна безпека із шифруванням файлів.
    #"iphlpsvc"                                      #Вимкнути ipv6. Хоч більшість мереж працюють на базі протоколу ipv4, вимкнення цієї служби ніяк не вплине на безпеку чи продуктивність. Нехай собі буде увімкнена.     
	
	#Три сервіси оновлення Edge. Якщо не користуєтесь Edge, є сенс вимкнути.
    #"edgeupdate"                                    
    #"MicrosoftEdgeElevationService"                 
   # "edgeupdatem"                                   
	
    "SEMgrSvc"                                      #Сервіс підтримки NFC та платежів через NFC. Якщо на ПК немає NFC, можна вимикати.
	
    #"PNRPsvc"                                      # Peer Name Resolution Protocol зазвичай використовується в сценаріях, де потрібна функціональність однорангових мереж. Наприклад, в однорангових додатках або при створенні домашніх груп для спільного використання файлів і принтерів в домашній мережі. Він дозволяє цим додаткам працювати без необхідності централізованого сервера для розв'язання імен. Вимкнення може наробити біди при роботі з мережею. На швидкодію не впливає.
	
    #"p2psvc"                                       # служба Peer Name Resolution Protocol створена для роботи домашніх груп. Вимкнення може наробити біди при роботі у мережі. На швидкодію ніяк не впливає.
	
    #"p2pimsvc"                                     # служба Peer Networking Identity Manager створена для роботи домашніх груп. Вимкнення може наробити біди при роботі у мережі. На швидкодію ніяк не впливає.
	
    #"PerfHost"                                      #зазвичай використовується для забезпечення роботи лічильників продуктивності, які збирають і обробляють дані про продуктивність системи. Сервіс забезпечує ізольоване середовище для виконання DLL, що зменшує ризик впливу помилок цих DLL на стабільність системи.На швидкодію ніяк не впливає, вимикати немає ніякого сенсу.
	
    #"cbdhsvc_48486de"                               #Clipboard User Service - служба буферу обміну. Якщо вимкнеш копіювання та вставка не працюватимуть. Вимикати рекомендується тільки дуже дивним людям.
	
    #"BluetoothUserService_48486de"                  #вимикає BluetoothUserService_48486de сервіс, що потрібен для функцінування Bluetooth. Користуєшся BlueTooth - не чіпай.
	
    #"WpnService"                                    #Вимикає WpnService (служба повідомлень Windows). Всі сповіщення перестануть працювати.
	
    #"StorSvc"                                       #сервіс для розпізнавання зовнішніх накопичувачів (флешок, жорстких дисків). Якщо вимкнеш - розпізнаватись не будуть. Ідеально для параноїків.
	
    #"RtkBtManServ"                                  #Вимикає Realtek Bluetooth Device Manager Service. Це сервіс потрібен для роботи Bluetooth пристроїв від Realtek.
	
    #"QWAVE"                                         #сервіс Quality Windows Audio Video Experience допомагає покращити якість потокового мультимедіа, знижуючи затримки і втрати пакетів, і оптимізуючи використання мережевих ресурсів.Немає сенсу вимикати.
	
     #Сервіси від HP. Якщо не користуєшся ними на ПК від HP, можна вимикати.
    #"HPAppHelperCap"
    #"HPDiagsCap"
    #"HPNetworkCap"
    #"HPSysInfoCap"
    #"HpTouchpointAnalyticsService"
    
	#Сервіси віртуалізації hyper-v. Потрібні для адекватної роботи віртуальних машин. Якщо не користуєшся віртуальними машинами, можна вимкнути, це трошки (зовсім) додасть швидкодії.
    # "HvHost"                          
    #"vmickvpexchange"
    #"vmicguestinterface"
    #"vmicshutdown"
    #"vmicheartbeat"
    #"vmicvmsession"
    #"vmicrdv"
    #"vmictimesync" 
	
    # Цей сервіс просто не чіпай ніколи. Він допомагає забезпечити безпеку системи, аналізуючи мережевий трафік та виявляючи потенційно небезпечні дії. Може миттєво перетворити твою систему в картоплину.
    #"WdNisSvc"
)

foreach ($service in $services) {
    #-При помилках тихенько продовжує, якщо не треба нічого змінювати, або сервіс не існує

    Write-Host  -ForegroundColor DarkMagenta "Встановлюємо автозапуск $service на вручну"
    Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Manual
}

Write-Host  -ForegroundColor DarkMagenta "Вимикаємо Пошук Bing у меню Пуск..."
    $ResultText.text = "`r`n" +"`r`n" + "Вимикаємо Пошук, Коритану, Пошук в меню Пуск... Зачекайте"
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0
    Write-Host  -ForegroundColor DarkMagenta "Вимикаємо Cortana"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    Write-Host  -ForegroundColor DarkMagenta "Приховуємо панель\кнопку пошуку..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

    Write-Host  -ForegroundColor DarkMagenta "Видаляємо плитки у меню Пуск..."

    Set-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -Value '<LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <LayoutOptions StartTileGroupCellWidth="6" />'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  <DefaultLayoutOverride>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <StartLayoutCollection>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:StartLayout GroupCellWidth="6" />'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </StartLayoutCollection>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '  </DefaultLayoutOverride>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    <CustomTaskbarLayoutCollection>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      <defaultlayout:TaskbarLayout>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        <taskbar:TaskbarPinList>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:UWA AppUserModelID="Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" />'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '          <taskbar:DesktopApp DesktopApplicationLinkPath="%APPDATA%\Microsoft\Windows\Start Menu\Programs\System Tools\File Explorer.lnk" />'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '        </taskbar:TaskbarPinList>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '      </defaultlayout:TaskbarLayout>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '    </CustomTaskbarLayoutCollection>'
    Add-Content -Path 'C:\Users\Default\AppData\Local\Microsoft\Windows\Shell\DefaultLayouts.xml' -value '</LayoutModificationTemplate>'

    $START_MENU_LAYOUT = @"
    <LayoutModificationTemplate xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout" xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" Version="1" xmlns:taskbar="http://schemas.microsoft.com/Start/2014/TaskbarLayout" xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
        <LayoutOptions StartTileGroupCellWidth="6" />
        <DefaultLayoutOverride>
            <StartLayoutCollection>
                <defaultlayout:StartLayout GroupCellWidth="6" />
            </StartLayoutCollection>
        </DefaultLayoutOverride>
    </LayoutModificationTemplate>
"@

    $layoutFile="C:\Windows\StartMenuLayout.xml"

    #Видаляє файл розкладки меню Пуск, якщо він існує
    If(Test-Path $layoutFile)
    {
        Remove-Item $layoutFile
    }

    #Створюємо пустий файл розкладки меню Пуск
    $START_MENU_LAYOUT | Out-File $layoutFile -Encoding ASCII

    $regAliases = @("HKLM", "HKCU")

    #Призначаємо початковий макет і примусово застосовуємо його за допомогою "LockedStartLayout" як на рівні машини, так і на рівні користувача
    foreach ($regAlias in $regAliases){
        $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
        $keyPath = $basePath + "\Explorer"
        IF(!(Test-Path -Path $keyPath)) {
            New-Item -Path $basePath -Name "Explorer"
        }
        Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 1
        Set-ItemProperty -Path $keyPath -Name "StartLayoutFile" -Value $layoutFile
    }

    #Перезапускаємо Explorer, відкриваємо меню Пуск (важливо, щоб завантажити нову розкладку), і даємо кілька секунд на пропрацювання
    Stop-Process -name explorer
    Start-Sleep -s 5
    $wshell = New-Object -ComObject wscript.shell; $wshell.SendKeys('^{ESCAPE}')
    Start-Sleep -s 5

    #Вмикаємо можливість закріпляти значки знову за допомогою "LockedStartLayout"
    foreach ($regAlias in $regAliases){
        $basePath = $regAlias + ":\SOFTWARE\Policies\Microsoft\Windows"
        $keyPath = $basePath + "\Explorer"
        Set-ItemProperty -Path $keyPath -Name "LockedStartLayout" -Value 0

    Write-Host  -ForegroundColor DarkMagenta "Search and Start Menu Tweaks Complete"
    $ResultText.text = "`r`n" +"`r`n" + "Search and Start Menu Tweaks Complete"
    }


$Bloatware = @(
    #Неважливі AppX застосунки у Windows
    "Microsoft.3DBuilder"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.AppConnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingWeather"
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingTravel"
    "Microsoft.MinecraftUWP"
    #"Microsoft.GamingServices"
    "Microsoft.WindowsReadingList"
    #"Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.News"
    "Microsoft.Office.Lens"
    "Microsoft.Office.Sway"
    "Microsoft.Office.OneNote"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    "Microsoft.Whiteboard"
    "Microsoft.WindowsAlarms"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsSoundRecorder"
    #"Microsoft.XboxApp"
    "Microsoft.ConnectivityStore"
    "Microsoft.CommsPhone"
    "Microsoft.ScreenSketch"
    #"Microsoft.Xbox.TCUI"
    #"Microsoft.XboxGameOverlay"
    #"Microsoft.XboxGameCallableUI"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.MixedReality.Portal"
    #"Microsoft.XboxIdentityProvider"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "Microsoft.YourPhone"
    "Microsoft.Getstarted"
    "Microsoft.MicrosoftOfficeHub"
    "Spotify"
    "Disney+"
    #"Xbox"
    "BytedancePte.Ltd.TikTok"   # TikTok
    "FACEBOOK.317180B0BB486"    # Messenger
    "FACEBOOK.FACEBOOK"         # Facebook
    "Facebook.Instagram*"       # Instagram / Beta
    "*Twitter*"                 # Twitter
    "*Viber*"
	"Clipchamp.Clipchamp"				     # Clipchamp – Video Editor
    "Microsoft.OutlookForWindows"            # Microsoft Outlook
    "MicrosoftTeams"                         # Microsoft Teams
    "MicrosoftWindows.Client.WebExperience"  # Taskbar Widgets

    #Спонсорські AppX застосунки у Windows
    #Ти можеш додати будь-які застосунки у форматі "*Назва застосунка*"
    "*EclipseManager*"
    "*ActiproSoftwareLLC*"
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
    "*Duolingo-LearnLanguagesforFree*"
    "*PandoraMediaInc*"
    "*CandyCrush*"
    "*BubbleWitch3Saga*"
    "*Wunderlist*"
    "*Flipboard*"
    "*Twitter*"
    "*Facebook*"
    "*Royal Revolt*"
    "*Sway*"
    "*Speed Test*"
    "*Dolby*"
    "*Viber*"
    "*ACGMediaPlayer*"
    "*Netflix*"
    "*OneCalendar*"
    "*LinkedInforWindows*"
    "*HiddenCityMysteryofShadows*"
    "*Hulu*"
    "*HiddenCity*"
    "*AdobePhotoshopExpress*"
    "*HotspotShieldFreeVPN*"
	"*LinkedIn*"
	"*ACGMediaPlayer*"
    "*ActiproSoftwareLLC*"
    "*AdobePhotoshopExpress*"           # Adobe Photoshop Express
    "Amazon.com.Amazon"                 # Amazon Shop
    "*Asphalt8Airborne*"                # Asphalt 8 Airbone
    "*AutodeskSketchBook*"
    "*BubbleWitch3Saga*"                # Bubble Witch 3 Saga
    "*CaesarsSlotsFreeCasino*"
    "*CandyCrush*"                      # Candy Crush
    "*COOKINGFEVER*"
    "*CyberLinkMediaSuiteEssentials*"
    "*DisneyMagicKingdoms*"
    "*Dolby*"                           # Dolby Products (Like Atmos)
    "*DrawboardPDF*"
    "*Duolingo-LearnLanguagesforFree*"  # Duolingo
    "*EclipseManager*"
    "*FarmVille2CountryEscape*"
    "*FitbitCoach*"
    "*Flipboard*"                       # Flipboard
    "*HiddenCity*"
    "*Keeper*"
    "*LinkedInforWindows*"
    "*MarchofEmpires*"
    "*NYTCrossword*"
    "*OneCalendar*"
    "*PandoraMediaInc*"
    "*PhototasticCollage*"
    "*PicsArt-PhotoStudio*"
    "*PolarrPhotoEditorAcademicEdition*"
    "*RoyalRevolt*"                     # Royal Revolt
    "*Shazam*"
    "*Sidia.LiveWallpaper*"             # Live Wallpaper
    "*Speed Test*"
    "*Sway*"
    "*WinZipUniversal*"
    "*Wunderlist*"
    "*XING*"
	"AmazonVideo.PrimeVideo"    # Amazon Prime Video
    "*Hulu*"
    "*iHeartRadio*"
    "*Netflix*"                 # Netflix
    "*Plex*"                    # Plex
    "*SlingTV*"
    "SpotifyAB.SpotifyMusic"    # Spotify
    "*TuneInRadio*"

    #Опціонально: немає сенсу видаляти, але якщо тобі треба з якоїсь причини.
    "*Microsoft.Advertising.Xaml*"
    #"*Microsoft.MSPaint*"
    #"*Microsoft.MicrosoftStickyNotes*"
    #"*Microsoft.Windows.Photos*"
    #"*Microsoft.WindowsCalculator*"
    #"*Microsoft.WindowsStore*"
)

    Write-Host  -ForegroundColor DarkMagenta "Видаляємо сміття"

    foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $Bloat -ErrorAction SilentlyContinue| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat -ErrorAction SilentlyContinue | Remove-AppxProvisionedPackage -Online
        Write-Host  -ForegroundColor DarkMagenta "Намагаємося видалити $Bloat."
        $ResultText.text = "`r`n" +"`r`n" + "Намагаємося видалити $Bloat."
    }

    Write-Host  -ForegroundColor DarkMagenta "Завершуємо видаляти сміттєві застосунки"
    $ResultText.text = "`r`n" +"`r`n" + "Видалення сміттєвих застосунків завершено."

#Покращуємо Windows Update
 Write-Host  -ForegroundColor DarkMagenta "Вимикаємо постачання драйверів через Windows Update..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
    Write-Host  -ForegroundColor DarkMagenta "Disabling Windows Update automatic restart..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
    Write-Host  -ForegroundColor DarkMagenta "Постачання драйверів через Windows Update вимкнено"
    $ResultText.text = "`r`n" +"`r`n" + "Виставляємо Windows Update на Дружні налаштування"

# Створюємо завдання на щотижневу точку відновлення
$taskName = "Щотижнева точка відновлення"
$taskDescription = "Створення щотижневої точки відновлення у неділю об 11:11"
$triggerTime = "11:11"
$checkpointDescription = "Щотижнева точка відновлення"

# Створити дію
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -Command `"Checkpoint-Computer -Description '$checkpointDescription' -RestorePointType 'MODIFY_SETTINGS'`""

# Створити тригер (щонеділі об 11:11)
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At $triggerTime

# Опціонально: Вказати параметри користувача та пароля
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

# Створити завдання
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Description $taskDescription

# Зареєструвати завдання
Register-ScheduledTask -TaskName $taskName -InputObject $task

Write-Host  -ForegroundColor DarkMagenta "Завдання '$taskName' було успішно створено."


# Створюємо завдання для автоматичного запуску SuperF4
$taskName = "SuperF4"
$taskDescription = "Автоматично запускає SuperF4"
$programPath = "$env:APPDATA\SuperF4\SuperF4.exe"

# Створити дію
$action = New-ScheduledTaskAction -Execute $programPath

# Створити тригер для запуску при вході будь-якого користувача
$trigger = New-ScheduledTaskTrigger -AtLogOn

# Створити принципала для завдання без зберігання пароля
$principal = New-ScheduledTaskPrincipal -UserId $env:UserName -LogonType Interactive -RunLevel Highest

# Створити налаштування для завдання
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DisallowHardTerminate

# Створити завдання
$task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $taskDescription

# Зареєструвати завдання з опцією 'run only when user is logged on'
Register-ScheduledTask -TaskName $taskName -InputObject $task -User $env:UserName -RunLevel Highest

Write-Host  -ForegroundColor DarkMagenta "Завдання '$taskName' було успішно створено."

#Зупиняємо створення логу скрипта.
Stop-Transcript

Write-Host -ForegroundColor Magenta "Налаштування Windows завершено"
#Чекати, щоб користувач прочитав.
Start-Sleep -s 5
Write-Host -ForegroundColor DarkYellow "Компуктер перезавантажиться через 10 секунд"
Start-Sleep -s 10
Restart-Computer

# SIG # Begin signature block
# MIIFcwYJKoZIhvcNAQcCoIIFZDCCBWACAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUOxkKzbBWhTMRe57k6CJbzVqB
# EAigggMMMIIDCDCCAfCgAwIBAgIQKNNiy9+rArtFpF7WvOVicTANBgkqhkiG9w0B
# AQsFADAcMRowGAYDVQQDDBFNeUNvZGVTaWduaW5nQ2VydDAeFw0yNDA3MDMxNzQz
# MTRaFw0yNTA3MDMxODAzMTRaMBwxGjAYBgNVBAMMEU15Q29kZVNpZ25pbmdDZXJ0
# MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuJI0EFvoMNFdsg+rkzEX
# /g5xdfAskfLV2I7hAVFJ8FX0PhYwfLQ7iI81Z/CUL4z6DeQVzwezPrCz/gs4YAJu
# yinhBQaxBoSDAg4QuVvhdXbFZNpxIi83dvyRgA+xLnU7jRDc2auRaRWNpvOOlTn2
# b3szzlhdLJQwwwgGWU5JvCnVYBI2tAB2aiE/hl5Th5SKHj36UU4WaSwHS9wUDqx5
# F2cJnLSUpffH2/4/SxlRQwiPuOQAO4Ds0buYTrdBAdLYCmo4NMRZ8owYp0PwF1eK
# c8gAuAmF6E9CZIH3xHFZvYdnCJu6cGzIKD2kIgbd1xMGPA+hIz3WaoltnenKKXdO
# jQIDAQABo0YwRDAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
# HQYDVR0OBBYEFDPrqLCc/q+PgskDkcRKI5E+XfzyMA0GCSqGSIb3DQEBCwUAA4IB
# AQAq/dVV5VYEb5GmjTzbCMwA9UWHeenr9PoSva8bcP16lwM1Eg4zUd6+h+W0s+/f
# KBMIpZziTmXDNRkvuRRBU/KIqbhWotJdS+IMqlP41s8zUVXzwLSoKz0KX0l/YSGa
# 7+yF6Zibxv/MkY5O4rN+ny7yErdcemSd/82qjaxjBRsCmH9Xw2Buq9YWs6GEfuY0
# gOAV6F1vDSjijKHVexIVRBeTs8JRFTfbv8X0As7EAYkXfLGNFI17UIPLZ4OdWG6B
# xqPdKiAeyDHr2Amo1V3C4XOSBkJM4ThXoqx9T3iFE8I+ZeqGeJHVfY4//ZY78NeE
# HTylEffI1bFS7wGSAcRJesyoMYIB0TCCAc0CAQEwMDAcMRowGAYDVQQDDBFNeUNv
# ZGVTaWduaW5nQ2VydAIQKNNiy9+rArtFpF7WvOVicTAJBgUrDgMCGgUAoHgwGAYK
# KwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIB
# BDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQU
# ql3VLH/O3qgcmTx1Y3rrcBy8NxowDQYJKoZIhvcNAQEBBQAEggEAK2UkacsZR+mS
# Xu81yofglWc35fE5W5UwAxoRJ23v55r50Jl52plJc0bbiSeYR/1BpgKLITTIu7vp
# gPBepSiphaqDqHI/0262gARXLNm5XgJpduBO7z5ygFB6WWL1aSZ44vJksVyj/yOp
# VGQLeKEXTVbA2Bl/JN71hJSlKTccKMMffugFbQl/8Q1btlf6nGNRfHyw5Oj8CdCP
# Y4lCWyklOau1bwfwhUOVJuZ7Rwcc+yuDGwTiXEGmruugGJ6jvuigxJz1v+SCCLCS
# uqbGbMuIckSed5okO0OJteoBJb05t/OMTpDJd6mFI2DkvdUIlVBihBtDz9E8M5Tp
# pjK8xVDkOA==
# SIG # End signature block
