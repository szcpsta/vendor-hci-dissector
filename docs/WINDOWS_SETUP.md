# Windows에서 Wireshark Lua dissector 개발하기

Windows에서도 **빌드 없이 Wireshark/TShark가 Lua 소스를 직접 로드**한다.
일반 Lua 실행 프로그램에는 Wireshark API가 없으므로 실제 패킷 해석은 Wireshark/TShark에서 확인한다.
배포·연결 단위는 레포 전체가 아니라 `vendor_hci` 폴더다.

이 문서의 명령은 **PowerShell** 기준이다. CMD나 Git Bash에 그대로 붙여 넣지 않는다.
Windows 실행은 이 작업 환경에서 직접 검증하지 못했다. Lua 예제와 필터는 macOS의
Wireshark 4.4.8/Lua 5.4.6으로 검증했으며, 아래 Windows 경로와 연결 방법은 공식 문서에 근거한다.
Windows 머신에서도 검증 명령을 실행해 버전별 동작을 확인한다.

## 1. 준비와 경로 설정

Wireshark와 `tshark.exe`, 테스트용 Python 3, Git을 준비한다.
기존 레포가 있다면 다시 clone하지 않고 그 경로를 사용한다.

```powershell
git clone git@github.com:szcpsta/vendor-hci-dissector.git C:\src\vendor-hci-dissector
```

설치·clone 위치가 다르면 아래 변수만 수정한다.

```powershell
$repoRoot = 'C:\src\vendor-hci-dissector'
$tsharkExe = Join-Path $env:ProgramFiles 'Wireshark\tshark.exe'
$wiresharkExe = Join-Path $env:ProgramFiles 'Wireshark\Wireshark.exe'
$luaEntry = Join-Path $repoRoot 'vendor_hci\init.lua'
$capturePath = Join-Path $env:TEMP 'vendor-hci-examples.btsnoop'
Set-Location -LiteralPath $repoRoot

& $tsharkExe --version
py -3 --version
```

PowerShell에서는 실행 파일 경로를 변수나 따옴표 문자열로 지정할 때 호출 연산자 `&`를 사용한다.
`py` 명령이 없지만 Python 3의 `python` 명령이 있다면 아래 `py -3`를 `python`으로 바꾼다.
이 예제는 로컬 캡처 파일을 읽는다. 실시간 캡처 권한이나 캡처 드라이버 설정은 별도 작업이다.

## 2. 설치 없이 먼저 실행하기

합성 btsnoop을 만들고 실제 TShark로 검사한다.

```powershell
py -3 tests\make_examples.py $capturePath --check $tsharkExe
if ($LASTEXITCODE -ne 0) { throw 'Dissector verification failed.' }
```

현재 기대 결과는 28개 값·진단 검사, 일반 분석과 두 번 분석의 일치, 208개 잘림 위치 검사다.
임시 plugin 폴더에 패키지를 복사해 `-X` 없이 자동 로드하는 검사도 포함한다.
이 검사는 `WIRESHARK_PLUGIN_DIR`을 해당 TShark 프로세스에만 지정하며 실제 설치 폴더를 수정하지 않는다.
`--check` 없이 실행하면 합성 파일만 만든다.

```powershell
$decodeArgs = @(
    '-n', '-r', $capturePath,
    '-X', "lua_script:$luaEntry",
    '-d', 'bthci_cmd.vendor=bthci_vendor.samsung',
    '-V'
)
& $tsharkExe @decodeArgs
```

여러 인수는 배열로 묶어 전달했다. 이 방식은 공백이 있는 경로를 한 인수로 유지하며,
PowerShell의 줄 연결용 backtick을 복사하다 생기는 실수를 줄인다.

GUI로 같은 파일을 여는 명령은 다음과 같다.

```powershell
& $wiresharkExe '-r' $capturePath '-X' "lua_script:$luaEntry" '-d' 'bthci_cmd.vendor=bthci_vendor.samsung'
```

현재 패키지의 프로토콜 이름은 `bthci_vendor.samsung`이고, Decode As 테이블은 `bthci_cmd.vendor`다.
이 테이블은 HCI Command와 Event가 공유하며, FT_NONE이므로 `bthci_cmd.vendor=bthci_vendor.samsung` 문법을 쓴다.
현재 실행 예제에도 Samsung 이름을 적용했다. payload layout은 계속 학습용이다.

## 3. 플러그인 폴더 확인

```powershell
& $tsharkExe -G folders
```

출력의 **Personal Lua Plugins**를 확인한다. GUI에서는 Help → About Wireshark → Folders에서도 볼 수 있다.
일반적인 경로는 `%APPDATA%\Wireshark\plugins`, 즉 사용자 프로필 아래
`AppData\Roaming\Wireshark\plugins`다. 실제 출력이 다르면 실제 경로를 사용한다.
버전별 C/C++ 바이너리 플러그인 하위 폴더와 Lua 폴더를 구분한다.
[Wireshark Plugin folders](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html),
[Windows folders](https://www.wireshark.org/docs/wsug_html_chunked/ChWindowsFolder.html).

## 4. 복사 또는 작업 폴더 연결

설치 없이 `-X`로 작업해도 충분하다. 자동 로드를 원하면 아래 **복사와 junction 중 한 가지만** 사용한다.
공통으로 경로를 준비한다.

```powershell
$sourcePath = Join-Path $repoRoot 'vendor_hci'
$pluginRoot = Join-Path $env:APPDATA 'Wireshark\plugins'
# -G folders의 Personal Lua Plugins가 다르면 $pluginRoot를 실제 경로로 바꾼다.
$pluginPath = Join-Path $pluginRoot 'vendor_hci'
New-Item -ItemType Directory -Path $pluginRoot -Force | Out-Null
```

### 방법 A: 폴더 복사

```powershell
if (Test-Path -LiteralPath $pluginPath) { throw "Existing installation: $pluginPath" }
Copy-Item -LiteralPath $sourcePath -Destination $pluginPath -Recurse
```

소스를 수정하면 설치된 복사본도 갱신한 뒤 Lua를 재로드한다.

### 방법 B: 로컬 작업 폴더를 junction으로 연결

로컬 NTFS 작업 폴더라면 directory junction을 사용할 수 있다.
다음 명령은 대상 이름에 기존 설치가 없을 때 사용한다.

```powershell
if (Test-Path -LiteralPath $pluginPath) { throw "Existing installation: $pluginPath" }
New-Item -ItemType Junction -Path $pluginPath -Target $sourcePath
Get-Item -LiteralPath $pluginPath | Select-Object FullName, LinkType, Target
```

junction은 디렉터리 연결 방식이며 Unix symbolic link와 동일한 객체는 아니다.
이 방식에서는 작업 파일을 수정한 뒤 따로 복사할 필요가 없다.
대상 경로가 네트워크 드라이브이거나 junction을 지원하지 않는 환경이면 복사 또는 `-X`를 사용한다.
Windows의 symbolic link도 가능하지만 Developer Mode나 권한 조건이 다를 수 있다.
[Microsoft New-Item](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/new-item?view=powershell-7.5),
[Microsoft mklink](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/mklink).

기존 대상이 있을 때 `-Force`로 덮어쓰지 말고 복사본인지 junction인지 먼저 확인한다.
깨진 연결은 `Test-Path`가 찾지 못할 수 있으며, 그 경우 생성 명령의 오류를 확인하고 기존 연결을 점검한다.

결과 구조는 다음과 같다.

```text
<Personal Lua Plugins>\
└── vendor_hci\             # 실제 폴더 또는 작업 폴더를 가리키는 junction
    ├── init.lua
    ├── samsung_dissector.lua
    ├── samsung_fields.lua
    ├── samsung_reader.lua
    ├── samsung_commands.lua
    ├── samsung_events.lua
    └── samsung_command_complete.lua
```

이 배치는 4.4.8의 개별 Lua 스캔과 `require()` 캐시를 함께 고려했다.
`init.lua`가 있다는 이유만으로 다른 파일이 자동 스캔되지 않는다고 가정하지 않는다.
예전 복사본을 갱신할 때는 폐기된 Lua 파일이 남지 않도록 설치 폴더 전체를 교체한다.

## 5. 자동 로드와 수정 후 재로드

복사/연결한 뒤에는 `-X`를 생략한다.

```powershell
& $tsharkExe '-n' '-r' $capturePath '-d' 'bthci_cmd.vendor=bthci_vendor.samsung' '-V'
```

GUI에서는 Wireshark를 다시 시작하고 Analyze → Decode As…에서 `BT HCI Vendor`의
프로토콜을 `Samsung HCI Vendor`로 선택한다. 후보 등록과 선택은 별개의 동작이다.

작업 순서는 `소스 수정 → Lua 재로드 또는 TShark 재실행 → 실제 패킷과 필터 확인`이다.

- Wireshark: Analyze → Reload Lua Plugins 또는 재시작.
- TShark: 명령을 다시 실행하면 새 프로세스에서 변경된 Lua를 읽는다.
- 파일 저장만으로 이미 실행 중인 Lua 상태가 바뀌지는 않는다. `require()`한 모듈도 재로드해야 한다.
- 설치/연결 방식과 `-X`로 같은 코드를 중복 로드하지 않는다.

## 6. 필터와 등록 확인

아래는 **설치 없이 `-X`를 사용하는 방식**이다. 설치/연결했다면 `-X`와 그 다음 인수를 뺀다.

```powershell
& $tsharkExe -G protocols | Select-String 'bthci_vendor'
& $tsharkExe -G fields -X "lua_script:$luaEntry" | Select-String 'bthci_vendor\.samsung\.(bd_addr|connection_handle)'

$filterArgs = @(
    '-n', '-r', $capturePath,
    '-X', "lua_script:$luaEntry",
    '-d', 'bthci_cmd.vendor=bthci_vendor.samsung',
    '-Y', 'bthci_vendor.samsung.bd_addr == aa:bb:cc:dd:ee:ff',
    '-T', 'fields', '-e', 'frame.number', '-e', 'bthci_vendor.samsung.bd_addr'
)
& $tsharkExe @filterArgs
```

PowerShell 문자열 안의 display filter는 한 인수로 전달한다. `-Y`는 해석 후 display filter이고,
`-f` capture filter가 Lua 필드를 검색하는 것은 아니다.
필드 이름과 표준 HCI를 함께 검색하는 방법은
[필드 식별자와 통합 필터 가이드](WIRESHARK_LUA_DISSECTOR_GUIDE.md#57-필드-식별자와-기존-wireshark-필터의-연동)에 있다.

## 7. 문제가 생겼을 때

| 현상 | 확인할 내용 |
|---|---|
| `Proto`를 찾지 못함 | 일반 `lua` 실행 프로그램으로 실행했는지 확인. TShark/Wireshark로 로드 |
| `bthci_vendor.samsung`이 유효하지 않음 | Lua 로드 오류, 잘못된 `-X` 경로, plugin 폴더, `init.lua` 존재 여부 |
| 프로토콜 중복 등록 오류 | 설치된 패키지와 `-X`의 중복, 다른 폴더의 이전 복사본 |
| 수정한 코드가 반영되지 않음 | 작업 파일과 복사본의 경로, junction Target, Lua 재로드 여부 |
| 필드 필터가 유효하지 않음 | plugin이 로드됐는지, 실제 abbreviation과 대소문자가 맞는지 |
| 필터 결과가 없음 | Decode As 선택, 캡처에 해당 필드가 실제 추가됐는지, 주소 순서·handle 값 |
| `py` 명령을 찾지 못함 | Python 3 설치 또는 사용 가능한 `python` 명령 확인 |

오류 상세는 TShark 표준 오류와 `-V` 출력, GUI의 Expert Info에서 확인한다.
주소와 handle이 같은 화면 label을 갖는다고 자동으로 함께 검색되지는 않는다.
필드명 통합과 연결 상태 추적은 별도 설계 항목이다.
