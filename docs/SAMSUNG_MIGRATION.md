# Samsung BT Status: 첫 실제 디코더 이관

BluetoothKit의 **`999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81`**
(`2026-06-11 07:07:44 +0900`, `Add VSE decoder sample (#37)`)에 구현된
`FwBuildIdEvent`를 Lua로 옮겼다. 이 문서에서 구현 근거는 해당 커밋의 코드이며,
검증 캡처의 FW Build ID 문자열은 합성 값이다. 실제 장비 로그나 추가 Samsung 명세는 사용하지 않았다.

## 지원 범위

| 경로 | 현재 동작 |
|---|---|
| Event `0xFF` → Subevent `0x63` → Tag `0x0000` | FW Build ID의 길이와 UTF-8 문자열 해석 |
| Subevent `0x63`의 다른 Tag | subevent/tag를 표시하고 남은 bytes를 `.raw`와 unknown 진단으로 보존 |
| 그 외 vendor subevent | subevent와 raw bytes, unknown 진단 |
| Vendor Command / Command Complete | 원본도 알려진 본문 파서가 없어 raw bytes와 unknown 진단 |

Command Complete의 Num HCI Command Packets와 opcode는 공통 HCI 처리에서 읽는다.
반환 본문의 첫 바이트를 무조건 Status라고 소비하지 않는다.
`samsung_events.lua`와 `samsung_command_complete.lua`의 분리는 유지한다.
프로토콜은 계속 `bthci_vendor.samsung` 하나다.

## wire 구조와 SG 대응

다음 offset은 **H4 packet type을 포함한 패킷 시작** 기준이다.
Lua vendor hook에는 H4 1바이트를 제외한 HCI 데이터가 들어온다.

| H4 offset | 크기 | 내용 | 원본 → Lua |
|---:|---:|---|---|
| 0 | 1 | H4 Event `0x04` | native H4 처리 |
| 1 | 1 | Event Code `0xFF` | native HCI + 공통 adapter |
| 2 | 1 | HCI Parameter Length = `4 + N` | 공통 adapter의 본문 경계 |
| 3 | 1 | Subevent `0x63` | `SamsungEventDispatch` → `samsung_events.lua` |
| 4 | 2 | Tag `0x0000`, little-endian | `BtStatusDispatch.TryReadU16` → `c:u(..., 2, ...)` |
| 6 | 1 | Length `N`, **바이트 수** | `byte Length`, `Dec` → `uint8`, `base.DEC` |
| 7 | N | FW Build ID | `CountFrom = Length`, `Utf8String` → `take(N)`, `ENC_UTF_8` |

예를 들어 `FW-1`은 다음 바이트다.

```text
04 | ff 08 | 63 | 00 00 | 04 | 46 57 2d 31
H4   HCI    sub  tag LE   N    "FW-1"
```

Length는 자기 자신·Tag·subevent를 제외한 문자열의 바이트 수다. UTF-8 한글 한 글자는
여러 바이트이므로 글자 수를 넣으면 안 된다. NUL 종료 문자열로 선언된 것이 아니며,
Length만큼의 바이트가 본문이다. `Length=0`은 허용한다.
HCI Parameter Length가 1바이트이고 이 이벤트의 고정 부분이 4바이트이므로
한 이벤트에 들어갈 FW Build ID는 최대 **251바이트**다.

원본의 본문 선언:

```csharp
[HciVendorDecoder("FW Build Id")]
public partial class FwBuildIdEvent : HciBtStatusEventDecoded
{
    [HciField("Length", Formatter = nameof(HciValueFormatter.Dec))]
    public byte Length { get; set; }
    [HciField("FW Build ID", CountFrom = nameof(Length), Formatter = nameof(HciValueFormatter.Utf8String))]
    public ReadOnlyMemory<byte> FwBuildId { get; set; }
}
```

[samsung_events_bt_status.lua](../vendor_hci/samsung_events_bt_status.lua)의 대응 본문:

```lua
local function decode_fw_build_id(c)
    local length = c:u(f.fw_build_id_length, 1, "FW Build ID Length")
    local value = c:take(length, "FW Build ID")
    local item = c.tree:add_packet_field(f.fw_build_id, value, ENC_UTF_8)
    if length > 0 then item:add(f.fw_build_id_bytes, value) end
end
```

Tag별 함수 테이블은 같은 모듈에 있다. 새 BT Status Tag를 추가할 때는 그 테이블에
본문 파서를 연결한다. HCI header/subevent와 최종 길이 검사를 각 파서에 복사하지 않는다.

## 필드 이름과 표시

모든 아래 접미사는 `bthci_vendor.samsung.` 뒤에 붙인다.

| 접미사 | 타입/표시 | 의미 |
|---|---|---|
| `subevent_code` | uint8, HEX + enum | `0x63` → BT Status, 기존 공통 필드 재사용 |
| `bt_status.tag` | uint16, HEX + enum | `0x0000` → FW Build ID, 다른 값도 숫자로 유지 |
| `bt_status.fw_build_id_length` | uint8, DEC | 문자열의 wire 바이트 수 |
| `bt_status.fw_build_id` | string, UTF-8 | 검색·추출할 FW Build ID |
| `bt_status.fw_build_id_bytes` | bytes | NUL·잘못된 UTF-8도 보존하는 원시 문자열 bytes. 길이 0이면 생략 |
| `raw` | bytes | 미지원 본문의 남은 bytes |

BT Status Tag를 가상 예제의 Message ID와 같은 필드로 취급하지 않는다.
길이도 다른 데이터 길이와 독립적으로 검색할 수 있도록 메시지 의미를 이름에 담았다.
공통 handle/address가 추가되는 메시지는 계속 `f.connection_handle`, `f.bd_addr`를 검토해 재사용한다.

```text
bthci_vendor.samsung.subevent_code == 0x63
bthci_vendor.samsung.bt_status.tag == 0x0000
bthci_vendor.samsung.bt_status.fw_build_id contains "2026"
bthci_vendor.samsung.bt_status.fw_build_id == ""
bthci_vendor.samsung.bt_status.fw_build_id_bytes == 41:00:42
```

enum의 표시 label이 바뀌어도 숫자 필터는 유지된다. 실제 bytes는 Packet Bytes 및 PDML의
해당 필드 range에서 확인할 수 있다. 문자열 표시에는 Wireshark의 UTF-8 변환과 출력 escaping이 적용된다.

**중간 NUL의 표시 차이는 의도적으로 구분한다.** `41 00 42`를 원본 C#은 `A\0B`로 유지하지만,
Wireshark 4.4.8의 FT_STRING은 `A`까지만 표시·문자열 필터에 사용하고 native `Trailing stray characters`
진단을 추가한다. 이관본은 선언된 3바이트를 모두 소비하며, 문자열 아래의 `.fw_build_id_bytes`에
`410042`를 보존한다. NUL 뒤 데이터까지 검색·추출하려면 bytes 필드를 사용한다.
임의의 NUL 제거·문자열 잘라 읽기·malformed 판정을 추가하지 않는다.
길이 0에서는 bytes 항목의 `<MISSING>` 표시를 피하려고 bytes 필드만 생략하고 빈 string 필드는 유지한다.

## unknown, malformed, truncated

- **unknown Tag**: 원본과 같이 이미 읽은 subevent와 Tag를 보존한다. 이후 body에 FW Build ID의
  Length 규칙을 적용하지 않는다. 원본 테스트 `04 ff 05 63 34 12 aa bb`는
  Tag `0x1234`, raw `aabb`가 된다.
- **malformed**: Tag/Length가 없거나, Length가 본문보다 크거나, 알려진 본문 뒤에 여분 bytes가 있다.
  원본 SG의 `TryReadBytes` 및 최종 `reader.IsEmpty` 검사에 대응한다.
- **truncated**: 캡처의 original length에는 필요한 bytes가 있지만 included length에는 없다.
  파일에 남은 bytes와 메시지가 선언한 길이를 구분해 진단한다.
- Lua는 오류가 나기 전까지 읽은 필드를 트리에 유지한다. 원본의 `HciInvalidDecoded` 객체를
  똑같이 재현하는 것이 아니라 Wireshark의 Expert Info로 오류를 표시한다.
- 원본 `Encoding.UTF8.GetString`은 잘못된 UTF-8에 replacement 문자를 사용한다.
  `A ff B` 입력은 이관본에서도 `A�B`로 표시되며 별도 malformed 판정을 추가하지 않는다.

native HCI에서 중단되는 너무 짧은 패킷은 Lua vendor hook에 도달하지 않을 수 있다.
또한 native의 `Event undecoded` Note와 이 plugin의 `.unknown` 진단은 구별해서 본다.

## 학습 예제와 실제 캡처

기존 `0xFC01`, `0xB0`, `0xA0:0x0001`, `0xE0`는
[samsung_tutorial.lua](../vendor_hci/samsung_tutorial.lua)에 모았다.
**기본값은 해석하지 않는 것**이다. Samsung에서 같은 숫자가 다른 의미로 쓰일 수 있기 때문이다.

학습 캡처에만 다음 옵션을 추가한다.

```text
-o bthci_vendor.samsung.enable_tutorial:TRUE
```

GUI에서는 Preferences → Protocols → Samsung HCI Vendor의
**Enable synthetic tutorial layouts**를 켠다. 실제 로그에서는 끈다.
Preference는 각 패킷을 분석할 때 읽으며, 학습 옵션을 켜도 실제 BT Status 경로가 우선한다.
예제 필드의 이름은 유지했으므로 기존 학습 필터는 옵션을 켜면 그대로 동작한다.
[Lua Pref API](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html),
[TShark 옵션](https://www.wireshark.org/docs/man-pages/tshark.html).

## 실행과 검증

레포 루트에서 다음을 실행한다. 설치/연결 상태라면 수동 실행 명령의 `-X`와 다음 인수를 뺀다.

```sh
python3 tests/check_samsung.py /tmp/samsung-bt-status.btsnoop --check tshark
tshark -n -r /tmp/samsung-bt-status.btsnoop \
  -X lua_script:vendor_hci/init.lua -d bthci_cmd.vendor=bthci_vendor.samsung \
  -Y bthci_vendor.samsung.bt_status.fw_build_id -T fields \
  -e frame.number -e bthci_vendor.samsung.bt_status.fw_build_id_length \
  -e bthci_vendor.samsung.bt_status.fw_build_id
```

macOS 앱 번들의 실행 파일은 `/Applications/Wireshark.app/Contents/MacOS/tshark`다.
Windows PowerShell:

```powershell
$tsharkExe = Join-Path $env:ProgramFiles 'Wireshark\tshark.exe'
$luaEntry = (Resolve-Path .\vendor_hci\init.lua).Path
$capturePath = Join-Path $env:TEMP 'samsung-bt-status.btsnoop'
py -3 tests\check_samsung.py $capturePath --check $tsharkExe
& $tsharkExe '-n' '-r' $capturePath '-X' "lua_script:$luaEntry" '-d' 'bthci_cmd.vendor=bthci_vendor.samsung' '-V'
```

`check_samsung.py`는 원본 테스트의 네 패킷과 wire 구조에서 만든 합성 패킷으로
23개 값·진단 case, 숫자·문자열 필터, 필드의 byte range, 일반/두 번 분석,
학습 옵션 격리, 367개 캡처 잘림 경계, 폴더 복사 자동 로드를 검사한다.
원본 커밋에는 정상 FW Build ID에 대한 테스트가 없어서 해당 정상·경계 입력을 새로 만들었다.

추가로 원본 커밋의 Core·Samsung·SG 소스를 임시 폴더에 추출해 **.NET SDK 9.0.202로 컴파일**하고,
같은 22개 완전한 H4 패킷을 원본 `HciDecoder(new SamsungVendorDecoder())`에 넣었다.
[고정된 원본 출력](../tests/fixtures/samsung_999c164.json)에 패킷·타입·필드를 기록했다.
TShark 검증은 이 원본 출력과 숫자·문자열·raw bytes·unknown/invalid 분류를 매번 비교한다.
원본 C#의 invalid 결과에 없는 Lua의 부분 필드와 위 NUL 표시 차이는 구분해서 비교한다.
캡처 잘림 한 건은 별도 검사이며 완전한 H4 패킷을 받는 이 C# 비교에는 넣지 않았다.

원본 출력은 `HciPacketParser.TryParse()` → `decoder.Decode()` → `decoded.BuildFields()`로 얻었다.
기준 snapshot은 해당 커밋을 다시 실행해 갱신하고, Lua 출력에서 기대값을 역으로 만들지 않는다.
이 C# 컴파일은 이관 시 비교 검증에만 사용했다. **plugin 실행·배포·일반 회귀 테스트에는 .NET이나 빌드가 필요 없다.**
기존 학습 회귀 검사는 `make_examples.py --check ...`로 별도로 실행하며 이 스크립트는 학습 옵션을 켠다.

Windows 명령은 [설치 가이드](WINDOWS_SETUP.md)를 함께 참고한다. 이번 실행 검증은 macOS에서 수행했다.

## 원본 및 API 전체 URL

코드 링크는 모두 실제로 읽은 revision에 고정했다. 원본 레포 접근 권한이 필요할 수 있다.

| 자료 | 전체 URL |
|---|---|
| 이관 기준 커밋 | `https://github.com/szcpsta/BluetoothKit/commit/999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81` |
| vendor 진입점 | `https://github.com/szcpsta/BluetoothKit/blob/999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81/src/BluetoothKit.Hci.Vendor.Samsung/SamsungVendorDecoder.cs` |
| subevent 분기 | `https://github.com/szcpsta/BluetoothKit/blob/999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81/src/BluetoothKit.Hci.Vendor.Samsung/Events/SamsungEventDispatch.cs` |
| Tag 분기 | `https://github.com/szcpsta/BluetoothKit/blob/999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81/src/BluetoothKit.Hci.Vendor.Samsung/Events/BtStatus/BtStatusDispatch.cs` |
| FW Build ID 선언 | `https://github.com/szcpsta/BluetoothKit/blob/999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81/src/BluetoothKit.Hci.Vendor.Samsung/Events/BtStatus/BtStatusEvents.cs` |
| 공통 header 필드 | `https://github.com/szcpsta/BluetoothKit/blob/999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81/src/BluetoothKit.Hci.Vendor.Samsung/HciSamsungDecoded.cs` |
| unknown 처리 | `https://github.com/szcpsta/BluetoothKit/blob/999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81/src/BluetoothKit.Hci.Vendor.Samsung/HciSamsungUnknownDecoders.cs` |
| Command 분기 | `https://github.com/szcpsta/BluetoothKit/blob/999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81/src/BluetoothKit.Hci.Vendor.Samsung/Commands/SamsungCommandDispatch.cs` |
| Command Complete 분기 | `https://github.com/szcpsta/BluetoothKit/blob/999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81/src/BluetoothKit.Hci.Vendor.Samsung/ReturnParameters/SamsungReturnParameterDispatch.cs` |
| 원본 회귀 테스트 | `https://github.com/szcpsta/BluetoothKit/blob/999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81/tests/BluetoothKit.Hci.Vendor.Samsung.Tests/SamsungVendorDecoderTests.cs` |
| 당시 SG | `https://github.com/szcpsta/BluetoothKit/blob/999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81/src/BluetoothKit.Generators/HciDecoderGenerator.cs` |
| 당시 reader | `https://github.com/szcpsta/BluetoothKit/blob/999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81/src/BluetoothKit.Core/LogTypes/BtSnoop/Common/HciSpanReader.cs` |
| 당시 UTF-8 formatter | `https://github.com/szcpsta/BluetoothKit/blob/999c164ab30f2f0fbb15cfe2f5f9a85e38b1bc81/src/BluetoothKit.Core/LogTypes/BtSnoop/Common/HciValueFormatter.cs` |
| Lua 필드·Preference API | `https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html` |
| Tree/encoding API | `https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html` |
| TShark CLI | `https://www.wireshark.org/docs/man-pages/tshark.html` |
