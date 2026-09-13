# Vendor HCI Dissector

Bluetooth HCI vendor decoder를 Wireshark Lua dissector로 이관하기 위한 레포지토리다.
현재는 BluetoothKit SG를 참고한 **실행 가능한 학습 예제와 마이그레이션 가이드**를 포함한다.
실제 vendor decoder 이관은 해당 구현과 wire 명세를 확보한 뒤 진행한다.

- [상세 작성·마이그레이션 가이드](docs/WIRESHARK_LUA_DISSECTOR_GUIDE.md)
- [Windows/PowerShell 실행·설치 가이드](docs/WINDOWS_SETUP.md)
- [실제 vendor 구현의 권장 패키지 구성](docs/PACKAGE_STRUCTURE.md)
- [Samsung 프로토콜·필드 이름 제안](docs/WIRESHARK_LUA_DISSECTOR_GUIDE.md#59-samsung-vendor의-이름을-정한다면)
- [참고자료와 전체 URL](docs/WIRESHARK_LUA_DISSECTOR_GUIDE.md#10-참고자료와-전체-url)
- [검증용 패킷과 기대값](tests/make_examples.py)

## 구조

```text
vendor-hci-dissector/
├── vendor_hci/                     # Wireshark에 설치할 패키지
│   ├── init.lua                    # 패키지 진입점
│   └── bkv_tutorial.lua            # 검증된 예제 dissector
├── docs/
│   ├── WIRESHARK_LUA_DISSECTOR_GUIDE.md
│   ├── WINDOWS_SETUP.md
│   └── PACKAGE_STRUCTURE.md
├── tests/
│   ├── fixtures/README.md          # 합성 캡처 생성·확장 방법
│   └── make_examples.py            # 패킷 생성 + TShark 통합 검증
└── README.md
```

Wireshark가 정한 유일한 레포지토리 구조는 없다. **플러그인 하위 디렉터리의 `init.lua`를
패키지 진입점으로 쓰는 것**은 Wireshark가 지원하는 로딩 규칙이고, 내부 코드와 문서·테스트 배치는
이 레포의 선택이다. 하위 Lua 파일은 `require()`로 로드한다.
[공식 로딩 규칙](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html),
[공식 모듈 예제](https://www.wireshark.org/docs/wsdg_html_chunked/wslua_require_example.html).

현재 구현은 여러 기법을 모은 단일 학습 모듈이다. 실제 vendor 구현에서는 공통 필드·reader·HCI 처리와
Command/Event/Command Complete 본문 파서를 분리하는 구성을 권장한다.
[패키지 구성 가이드](docs/PACKAGE_STRUCTURE.md)에 Samsung을 가정한 파일 배치와 새 메시지 추가 예를 정리했다.
필드·프로토콜 등록은 패킷 콜백 밖에서 한 번 수행하고, 순서가 필요한 모듈은 명시적으로 로드한다.

## 요구 환경

- 검증 환경: **Wireshark/TShark 4.4.8, 내장 Lua 5.4.6**.
- 예제 패킷 생성과 검증: **Python 3**, 표준 라이브러리만 사용.
- 다른 Wireshark/Lua 버전은 아래 검증 명령으로 확인한다.

Wireshark가 내장 Lua와 API를 제공하며, `vendor_hci/init.lua`를 로드하면 프로토콜이 등록된다.
현재 프로토콜 필터 이름은 `bkv`, 표시 이름은 `BluetoothKit Vendor Tutorial`이다.
별도 Lua 실행 프로그램이나 빌드 과정은 필요하지 않다. 일반 `lua` 명령에는 Wireshark API가
없으므로, 실제 dissector 실행과 검증은 Wireshark/TShark로 한다.

## 빠른 실행

Windows에서는 PowerShell에서 레포지토리 루트로 이동한 뒤 실행한다.

```powershell
$tsharkExe = Join-Path $env:ProgramFiles 'Wireshark\tshark.exe'
$luaEntry = (Resolve-Path .\vendor_hci\init.lua).Path
$capturePath = Join-Path $env:TEMP 'vendor-hci-examples.btsnoop'
py -3 tests\make_examples.py $capturePath --check $tsharkExe
& $tsharkExe '-n' '-r' $capturePath '-X' "lua_script:$luaEntry" '-d' 'bthci_cmd.vendor=bkv' '-V'
```

설치 경로가 다르면 변수를 수정한다. GUI 실행, 폴더 복사와 junction 연결은
[Windows 가이드](docs/WINDOWS_SETUP.md)에 있다. Windows에서 직접 검증한 결과는 아직 없으며,
아래 검증 결과는 macOS의 Wireshark 4.4.8을 기준으로 한다.

레포지토리 루트에서 실행한다. `tshark`가 PATH에 있는 환경의 예:

```sh
python3 tests/make_examples.py /tmp/vendor-hci-examples.btsnoop --check tshark

tshark -n -r /tmp/vendor-hci-examples.btsnoop \
  -X lua_script:vendor_hci/init.lua \
  -d bthci_cmd.vendor=bkv -V
```

macOS의 Wireshark 앱 번들을 사용하는 경우:

```sh
python3 tests/make_examples.py /tmp/vendor-hci-examples.btsnoop \
  --check /Applications/Wireshark.app/Contents/MacOS/tshark

/Applications/Wireshark.app/Contents/MacOS/Wireshark \
  -r /tmp/vendor-hci-examples.btsnoop \
  -X lua_script:vendor_hci/init.lua \
  -d bthci_cmd.vendor=bkv
```

`bthci_cmd.vendor`는 Command와 Event가 공유하는 FT_NONE 테이블이다.
4.4.8에서 사용하는 CLI 문법은 **`-d bthci_cmd.vendor=bkv`**다.
예제는 Decode As 후보를 등록하며 특정 Company ID에 자동 연결하지 않는다.

## 설치

```sh
tshark -G folders
```

출력의 **Personal Lua Plugins** 폴더 안에 `vendor_hci` 폴더 전체를 복사한다.
Windows의 일반적인 경로는 `%APPDATA%\Wireshark\plugins`이며 실제 `-G folders` 출력을 우선한다.

```text
<Personal Lua Plugins>/
└── vendor_hci/
    ├── init.lua
    └── bkv_tutorial.lua
```

Wireshark를 다시 시작한 뒤 Analyze → Decode As…에서 `BT HCI Vendor`의 프로토콜을
`BluetoothKit Vendor Tutorial`로 선택한다. 설치 후에는 `-X lua_script` 없이 로드된다.
설치 방식과 개발용 `-X` 방식 중 하나를 사용해 중복 로드를 피한다.
문서·테스트를 포함한 레포 전체 대신 `vendor_hci` 폴더만 설치한다.

### 작업 폴더를 직접 연결하기

macOS/Linux에서는 복사 대신 심볼릭 링크를 사용할 수 있다. `tshark -G folders`로 확인한
Personal Lua Plugins 경로를 사용한다. 다음은 가이드 작성 머신의 경로다.

```sh
mkdir -p /Users/kihunahn/.local/lib/wireshark/plugins
ln -s /Users/kihunahn/RiderProjects/vendor-hci-dissector/vendor_hci \
  /Users/kihunahn/.local/lib/wireshark/plugins/vendor_hci
```

대상에 이미 `vendor_hci` 디렉터리나 링크가 있다면 먼저 기존 설치를 확인한다.
위 명령은 대상 이름이 없을 때 사용하는 예다. Windows에서는 폴더를 복사하거나
[Windows 가이드의 junction 방식](docs/WINDOWS_SETUP.md#방법-b-로컬-작업-폴더를-junction으로-연결)을 사용할 수 있다.
링크를 사용하면 소스 파일을 수정할 때마다 복사할 필요가 없다.

### 수정 후 반영하기

`코드 수정 → Lua 재로드 또는 TShark 재실행 → 패킷·필터 확인` 순서로 작업한다.

- TShark: 같은 명령을 다시 실행한다. 새 프로세스가 변경된 파일을 읽는다.
- Wireshark: Analyze → Reload Lua Plugins를 사용하거나 재시작한다.
- 실행 중인 Lua 상태가 파일 저장만으로 자동 갱신되지는 않는다. `require()`한 모듈도 재로드 대상이다.
- 설치/링크 방식에서는 `-X`를 생략하고, `-X` 방식에서는 같은 패키지를 설치 폴더에서 중복 로드하지 않는다.

이 레포에서는 별도 빌드 산출물 없이 `vendor_hci` 폴더가 배포 단위다.

## 기존 HCI 필드와 함께 필터링하기

필터의 식별자는 내부 숫자 ID나 화면의 `BD_ADDR` label이 아니라
`bkv.address`, `bthci_evt.bd_addr` 같은 **필터 이름(abbreviation)**이다.
같은 주소 타입이나 같은 표시 이름만으로 다른 필드가 자동으로 묶이지 않는다.

```text
bluetooth.addr == aa:bb:cc:dd:ee:ff ||
bthci_cmd.bd_addr == aa:bb:cc:dd:ee:ff ||
bthci_evt.bd_addr == aa:bb:cc:dd:ee:ff ||
bkv.address == aa:bb:cc:dd:ee:ff
```

`bluetooth.addr`는 모든 BD_ADDR 필드의 자동 집합이 아니라 출발지·목적지 검색용 필드다.
handle도 Command/Event/ACL/vendor의 실제 필터 이름을 명시적으로 묶어야 한다.
이름을 통일해도 다른 frame의 address와 handle을 자동으로 연결하지는 않는다.

공통 vendor 필드 규칙, 기존 필터 이름의 의도적인 공유, handle 수명과 address type은
[가이드의 필드 식별자·통합 필터 절](docs/WIRESHARK_LUA_DISSECTOR_GUIDE.md#57-필드-식별자와-기존-wireshark-필터의-연동)에 설명했다.
이 프로젝트에서는 자체 vendor namespace를 사용하고 Command/Event의 공통 필드를 재사용한다.
새 디코더를 추가할 때는 [필드 관리 규칙](docs/WIRESHARK_LUA_DISSECTOR_GUIDE.md#이-프로젝트의-필드-관리-규칙)에 따라
기존 정의의 의미·타입·단위를 먼저 확인한다. 공식 Lua API에서 필터 이름의 매개변수는 `abbr`다.

## 예제의 범위

- `0xFC01`, `0xB0`, `0xA0:0x0001`: BluetoothKit SampleVendorContract와 대응.
- `0xE0` 하위 메시지: **학습용으로 정의한 가상 vendor protocol**.
- 조건부 본문, optional field, 동적 길이, 고정·가변 구조체 배열, TLV, context 인수,
  비트필드 count, 주소·enum·단위 표시를 포함한다.
- 실제 회사의 vendor wire 명세를 구현한 것으로 간주하지 않는다.

## 검증

`make_examples.py`는 합성 H4 btsnoop과 기대값을 사용한다. `--check`를 주면 실제 TShark에
패키지 진입점 `vendor_hci/init.lua`를 로드해 검사한다.

- 28개 패킷의 필드 값과 unknown/malformed/truncated 분류.
- 일반 분석과 `tshark -2` 재분석 결과 일치.
- 208개 바이트 경계에서 캡처를 잘라도 Lua Error가 발생하지 않는지 확인.

```sh
python3 tests/make_examples.py /tmp/vendor-hci-examples.btsnoop --check tshark
```

배열·주소 등의 개별 필드를 추출할 수도 있다.

```sh
tshark -n -r /tmp/vendor-hci-examples.btsnoop \
  -X lua_script:vendor_hci/init.lua -d bthci_cmd.vendor=bkv \
  -Y bkv -T fields -E header=y -E occurrence=a \
  -e frame.number -e bkv.address -e bkv.rssi -e bkv.step.data -e bkv.malformed
```

## 실제 vendor decoder 이관

route 표와 소비된 header 범위부터 확정하고, 필드 타입·길이·selector·표시 규칙을 옮긴다.
기존 decoder와 같은 원시 바이트를 넣어 숫자·배열·주소·오류 처리를 비교한다.
상세 순서는 [가이드의 마이그레이션 절](docs/WIRESHARK_LUA_DISSECTOR_GUIDE.md#기존-vendor-decoder를-확보한-뒤의-순서)에 있다.

이 패키지는 Wireshark/TShark에서 동작한다. BluetoothKit CLI/MCP에서 사용하려면
TShark 호출 및 출력 변환을 별도 통합한다.
