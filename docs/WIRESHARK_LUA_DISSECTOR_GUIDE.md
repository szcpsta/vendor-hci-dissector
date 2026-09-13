# SG 기반 vendor decoder를 Wireshark Lua dissector로 옮기기

이 가이드는 현재 BluetoothKit의 Source Generator(SG), 공개된 SampleVendorContract,
로컬 Wireshark 소스를 바탕으로 작성했다. 접근할 수 없는 기존 vendor decoder의 실제
레이아웃을 추정하지 않는다. **SG의 필드 읽기 규칙은 Lua 함수로, 출력 정의는
`ProtoField`로, vendor dispatch는 Lua 함수 테이블로 옮기는 방식**을 설명한다.

확인 환경은 설치된 **Wireshark/TShark 4.4.8, Lua 5.4.6**이다.
`/Users/kihunahn/Downloads/wireshark-master`는 호출 경로와 구현을 읽는 데 사용했다.
이 소스 트리의 동작과 설치 바이너리가 항상 같다고 가정하지 않는다.

## 읽는 순서와 실행 파일

1. [기본 개념](#1-기본-개념): Proto, ProtoField, Tvb, TreeItem, Pinfo.
2. [설치·실행](#2-예제를-직접-실행하기): 실제 btsnoop과 Decode As.
3. [HCI 진입점](#3-hci에서-정확히-어디에-연결되는가): Command/Event/Command Complete 오프셋.
4. [SG 대응표](#4-sg와-lua의-대응): 무엇을 그대로 옮기고 무엇을 바꾸는가.
5. [출력 형태](#5-출력-형태-주소-enum-비트필드-단위-시간): 필터 가능한 타입과 표시 문자열.
6. [레이아웃 예제](#6-레이아웃별-예제): 조건, 배열, 동적 길이, StructArg, TLV.
7. [malformed의 책임](#7-malformed-처리는-얼마나-직접-해야-하는가): 자동 처리와 직접 검사의 경계.
8. [개발·마이그레이션](#8-필터-출력-재분석과-마이그레이션): 테스트, 출력, 상태, 이관 순서.
9. [구현 간 차이](#9-작성자에-따라-구현이-얼마나-달라지는가): 비슷해지는 부분과 동작을 달리하는 선택.
10. [참고자료와 전체 URL](#10-참고자료와-전체-url): 공식 문서와 구현 소스의 주소.

완성된 실행 코드는 [bkv_tutorial.lua](../vendor_hci/bkv_tutorial.lua)에 있다.
[make_examples.py](../tests/make_examples.py)는 합성 btsnoop 파일을 만들고
선택적으로 TShark로 검사한다. Python 표준 라이브러리만 사용한다.

이 레포에서는 [vendor_hci/init.lua](../vendor_hci/init.lua)가 위 예제 모듈을 `require()`로 로드한다.
명령과 상대 경로는 이 레포지토리에 맞췄으며, BluetoothKit의 SG 소스는 revision을 고정한 외부 링크로 참조한다.

`0xFC01`, `0xB0`, `0xA0:0x0001`은 프로젝트 SampleVendorContract를 따른다.
**`0xE0` 아래의 메시지와 status/action/TLV enum은 설명용 가상 프로토콜**이다.
CS step은 현재 SG의 entry 레이아웃을 재사용하지만, 예제의 HCI envelope는 가상 vendor event다.
실제 LE CS event 전체나 특정 회사의 프로토콜 구현으로 사용하면 안 된다.

## 1. 기본 개념

dissector는 Wireshark가 넘기는 바이트를 해석하고, 해당 패킷의 상세 트리에 필드를 추가하는 함수다.
호출 구조는 다음과 같다.

```text
btsnoop 파일 읽기              Wireshark
  → Bluetooth / H4             Wireshark
    → HCI Command 또는 Event   Wireshark
      → vendor Lua 진입점      우리가 작성
        → route / message ID
          → 본문 파서
            → ProtoField를 TreeItem에 추가
```

| 객체 | 역할 | BluetoothKit에서 가까운 개념 |
|---|---|---|
| `Proto` | 프로토콜 등록, dissector 함수와 필드·설정 보유 | 디코더와 등록 정보 |
| `ProtoField` | 필드 이름·타입·필터 이름·enum·mask 정의 | `FieldDefinition` + 타입 + Formatter 일부 |
| `Tvb` | 이번 호출에 전달된 패킷 버퍼 | reader가 바라보는 바이트 영역 |
| `TvbRange` | 버퍼의 offset/length 구간 | span slice |
| `TreeItem` | 상세 트리의 노드, 필드 추가·설명 부착 | `IFieldWriter` / field tree |
| `Pinfo` | frame 번호, 방향, 컬럼, 재분석 여부 등 | 패킷 메타데이터 |
| `DissectorTable` | 상위 프로토콜이 하위 dissector를 선택하는 테이블 | dispatch table |
| `ProtoExpert` | 오류·주의·미해석 내용을 필터 가능한 진단으로 등록 | decode failure의 사용자 표시 부분 |

`ProtoField`는 **값을 읽는 명령이 아니라 필드 정의**다. 패킷마다 생성하지 않고
파일 로드 시 한 번 만들고 `proto.fields`에 등록한다. 패킷 값은 `tvb(...)`에서 읽는다.

기본 문법만 보여 주는 UDP 예제는 다음과 같다. 실제 HCI에 붙이는 코드는 3절과 완성 파일을 따른다.

```lua
local demo = Proto("sgdemo", "SG Demo")
local value_f = ProtoField.uint16("sgdemo.value", "Value", base.HEX)
local short_e = ProtoExpert.new("sgdemo.short", "Value requires two bytes",
    expert.group.MALFORMED, expert.severity.ERROR)
demo.fields = {value_f}
demo.experts = {short_e}

function demo.dissector(tvb, pinfo, tree)
    local t = tree:add(demo, tvb())
    if tvb:captured_len() < 2 then
        t:add_proto_expert_info(short_e)
        return tvb:captured_len()
    end
    t:add_le(value_f, tvb(0, 2))
    pinfo.cols.protocol = "SGDEMO"
    return tvb:captured_len()
end

DissectorTable.get("udp.port"):add(50000, demo)
```

`34 12`를 받으면 `Value: 0x1234`로 표시되고 `sgdemo.value == 0x1234`로 필터링된다.
이 최소 예제의 짧은 입력 진단은 단순화한 것이다. 캡처 잘림과 메시지 자체의 길이 오류는
7절 및 완성 예제처럼 구분할 수 있다.

Lua에서 주의할 점:

- `tvb` offset은 **0부터**, 일반 Lua 배열은 보통 **1부터** 시작한다.
- `0`도 참이다. `if status then`은 성공/실패 판별이 아니다. `status == 0`처럼 비교한다.
- `nil`은 값 없음이다. `local v = extractor()`로 받은 뒤 존재 여부를 확인한다.
- `:`는 메서드에 자기 객체를 전달한다. `tvb:captured_len()`, `tree:add(...)`처럼 사용한다.
- wire 순서는 명시적인 함수 호출이나 배열로 정한다. `pairs()`의 순회 순서에 의존하지 않는다.
- 여러 바이트 HCI 정수는 보통 LE지만, vendor wire spec을 우선한다.

기본 객체와 등록 방식은 [공식 Proto API](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html),
바이트 읽기는 [Tvb API](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html)를 참고한다.

## 2. 예제를 직접 실행하기

vendor-hci-dissector 레포지토리 루트에서 실행한다. 아래 경로는 이 머신에 설치된 프로그램 경로다.

```sh
python3 tests/make_examples.py /tmp/bkv.btsnoop \
  --check /Applications/Wireshark.app/Contents/MacOS/tshark

/Applications/Wireshark.app/Contents/MacOS/tshark \
  -n -r /tmp/bkv.btsnoop \
  -X lua_script:vendor_hci/init.lua \
  -d bthci_cmd.vendor=bkv \
  -V
```

`bthci_cmd.vendor`는 FT_NONE 테이블이다. **이 환경에서 확인한 CLI 문법은
`-d bthci_cmd.vendor=bkv`**다. UDP에서 쓰는 `udp.port==50000,sgdemo` 문법을 그대로 쓰지 않는다.

GUI로 실행하려면 다음처럼 스크립트와 Decode As를 함께 지정할 수 있다.

```sh
/Applications/Wireshark.app/Contents/MacOS/Wireshark \
  -r /tmp/bkv.btsnoop \
  -X lua_script:vendor_hci/init.lua \
  -d bthci_cmd.vendor=bkv
```

수동으로는 패킷 선택 → Analyze → Decode As…에서 `BT HCI Vendor` 테이블의
현재 프로토콜을 `BluetoothKit Vendor Tutorial`로 선택한다. Event에서도 같은 테이블을 사용한다.
`add_for_decode_as()`는 후보에 등록하는 동작이므로 선택 전에는 자동으로 실행되지 않는다.

계속 사용할 때는 다음 명령으로 **Personal Lua Plugins** 폴더를 확인하고 `vendor_hci` 폴더 전체를 복사한다.

```sh
/Applications/Wireshark.app/Contents/MacOS/tshark -G folders
```

이 머신에서는 `/Users/kihunahn/.local/lib/wireshark/plugins`다.
`Personal Plugins`의 버전별 바이너리 플러그인 폴더와 구분한다. 폴더는 OS·설치에 따라 다르므로
고정 경로를 일반 규칙으로 사용하지 않는다. 재시작하면 스크립트를 로드한다.
같은 파일을 플러그인 폴더와 `-X lua_script:...`에서 중복 로드하지 않는다.
개발 중에는 이 레포의 `vendor_hci/init.lua`를 `-X`로 로드한다. 영구 설치와 `-X` 중 한 가지 방식을 사용한다.

자동 로드와 패키지의 `init.lua` 규칙은 [공식 Lua 로딩 설명](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html),
폴더 규칙은 [Plugin folders](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html)에 있다.

## 3. HCI에서 정확히 어디에 연결되는가

### 등록 테이블

로컬 바이너리에서 다음 명령으로 확인했다.

```sh
/Applications/Wireshark.app/Contents/MacOS/tshark -G dissector-tables \
  | rg 'bthci|bluetooth.vendor|hci_h4.type'
```

| 테이블 | 선택 키 | 용도 |
|---|---|---|
| `bthci_cmd.vendor` | FT_NONE, Decode As | HCI vendor dissector를 수동 선택. Command와 Event가 공유 |
| `bluetooth.vendor` | FT_UINT16, manufacturer/company ID | 컨트롤러 제조사 정보에 따른 선택 |
| `hci_h4.type` | H4 packet type | Command/Event 등 HCI 전체 계층을 선택 |
| `btcommon.eir_ad.manufacturer_company_id` | AD의 Company ID | 광고 데이터의 Manufacturer Specific Data; HCI vendor와 별개 |

처음에는 다음 등록만 사용하면 된다.

```lua
DissectorTable.get("bthci_cmd.vendor"):add_for_decode_as(p)
```

`bthci_cmd.opcode`나 `bthci_evt.code`는 **표시 필드 이름**이다.
같은 이름의 dispatch table이 있다고 생각하고 `DissectorTable.get()`에 넣으면 안 된다.
opcode·vendor subevent·message ID별 분기는 우리 Lua 코드가 한다.

제조사별 자동 선택을 원하면 실제 Company ID를 확인한 뒤
`DissectorTable.get("bluetooth.vendor"):add(company_id, p)`를 고려할 수 있다.
이 경로는 Wireshark가 해당 adapter의 manufacturer를 알고 있어야 한다.
중간부터 시작한 로그에는 필요한 초기화 정보가 없을 수 있다. 이미 같은 Company ID를 담당하는
기본 dissector가 있는지도 확인한다. 샘플은 임의의 Company ID를 등록하지 않는다.

Decode As는 opcode 하나만 선택하는 설정이 아니다. 여러 컨트롤러나 vendor가 섞인 캡처에 적용할
때는 적용 범위를 고려하고, 진입점이 자기 프로토콜을 식별할 수 있게 설계한다.
아직 자신의 패킷인지 확인하지 못했다면 트리·컬럼을 바꾸기 전에 `return 0`으로 거절한다.
자신의 프로토콜로 확인된 unknown 메시지와 이 거절 경로를 구분한다.

### 전달되는 바이트

이 테이블에는 **H4 packet-type byte가 제거된 HCI 패킷 전체**가 전달된다.
현재 `IVendorDecoder`처럼 routing/header가 전부 소비된 reader가 전달되는 것이 아니다.

| 입력 종류 | Lua `tvb`의 바이트 순서 | vendor 본문 시작 offset |
|---|---|---:|
| Command | `Opcode:u16le, ParameterLength:u8, Parameters...` | 3 |
| Vendor Event | `EventCode=FF, ParameterLength:u8, VendorParameters...` | 2 |
| Command Complete | `0E, ParameterLength, NumCmdPackets, Opcode:u16le, ReturnParameters...` | 5 |
| Command Status | `0F, ParameterLength, Status, NumCmdPackets, Opcode:u16le` | 표준 고정 구조 |

예를 들어 btsnoop의 H4 바이트가 다음과 같으면:

```text
04 FF 04 A0 01 00 44
│  │  │  └─ VendorParameters
│  │  └─ HCI parameter length = 4
│  └─ Vendor Event
└─ H4 Event type

Lua tvb: FF 04 A0 01 00 44
offset:   0  1  2  3  4  5
```

Lua에서 `A0`와 `Message ID = 1`을 읽고 나서야 Sample Value의 시작점인 offset 5에 도달한다.
이 경계를 먼저 정해야 기존 decoder의 필드 오프셋을 두 번 이동시키는 실수를 막을 수 있다.

완성 예제는 상위 HCI dissector가 이미 만든 필드로 Command/Event를 구분한다.

```lua
-- 파일 로드 시 준비한다. dissector 안에서 Field.new를 만들지 않는다.
local event_code = Field.new("bthci_evt.code")
local command_opcode = Field.new("bthci_cmd.opcode")

-- dissector 안:
local ev, op = event_code(), command_opcode()
if ev then
    -- Event. opcode가 필요한 CC/CS에서는 event tvb의 지정 위치에서 읽는다.
elseif op then
    -- Command.
else
    return 0
end
```

이 방식은 문서에서 확인하고 테스트한 **native HCI → vendor hook 경로**를 위한 것이다.
다른 상위 dissector, 다중 HCI encapsulation, 임의 postdissector에 그대로 적용하지 않는다.
`Field.new()`의 시점과 필드 접근은 [공식 Field API](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Field.html)를 참고한다.

상위 HCI dissector가 opcode·event code·command-response 연결 등을 표시하므로 vendor tree에서는
본문을 중심으로 추가할 수 있다. 외부 vendor 코드를 이관할 때도 `DecodeCommand`,
`DecodeCommandComplete`, `DecodeEvent`에 대응하는 내부 함수는 나누는 것이 읽기 쉽다.

로컬 소스 근거: `epan/dissectors/packet-bthci_cmd.c`의 `dissect_bthci_cmd`,
`packet-bthci_evt.c`의 `dissect_bthci_evt_command_complete`, vendor event 분기 및
`proto_reg_handoff_bthci_evt`. 설치 버전의 공개 소스도
[Command](https://github.com/wireshark/wireshark/blob/wireshark-4.4.8/epan/dissectors/packet-bthci_cmd.c),
[Event](https://github.com/wireshark/wireshark/blob/wireshark-4.4.8/epan/dissectors/packet-bthci_evt.c)에서 확인할 수 있다.

## 4. SG와 Lua의 대응

| 현재 SG/모델 | Lua에서의 대응 |
|---|---|
| `[HciVendorDecoder]` + 수동 dispatch | Proto + opcode/subevent/message 함수 테이블 |
| `[HciField] byte/ushort/uint` | uint8/16/32 ProtoField + `add_le`, 분기용 값은 `le_uint()` |
| `sbyte/short/int` | int8/16/32 ProtoField + `int()` 또는 `le_int()` |
| `uint, Size=3` | uint24 ProtoField, 3-byte range |
| `ulong, Size=5/6` | uint64 ProtoField, 5/6-byte range |
| `ReadOnlyMemory<byte>, Size=N` | bytes/address/string field에 N-byte range |
| `CountFrom` on bytes | 앞의 길이를 읽고 그 길이만큼 range 소비 |
| `CountFrom` on scalar array | 원소 개수만큼 같은 ProtoField를 반복 추가 |
| `CountFrom` on `[HciStruct]` array | 원소 개수만큼 구조체 파서 호출, entry subtree 생성 |
| `Count=N` | 고정 횟수 반복; N은 원소 개수 |
| `[HciStruct]` | 다음 offset을 반환하거나 공유 cursor를 진행시키는 함수 |
| `StructArg` | 일반 Lua 함수 인수 `decode_struct(cursor, selector)` |
| `[HciBitField]` | 원본 container range + mask가 설정된 ProtoField |
| `Formatter` | enum table, field type, display base, 단위, 추가 text, 계산 필드 |
| `AppendFields` / `BuildFields` | `tree:add`, subtree 생성 |
| route initializer / 자동 header 출력 | HCI adapter에서 읽기 위치 결정 + 기존 HCI tree 활용 |
| top-level `reader.IsEmpty` 검사 | 본문 파싱 뒤 소비 offset과 본문 끝 비교 |
| `MalformedWithPrefix` | 이미 추가된 tree prefix + ProtoExpert; partial model은 불필요 |

현재 SG는 `StructArg`를 단일 구조체 필드에 지원하고, context가 필요한 구조체 배열은 수동 wrapper로
처리한다. Lua에서는 각 원소 파서에 필요한 context를 직접 전달할 수 있다.

원본: [SG 작성 가이드](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/docs/HCI_DECODER_AUTHORING_GUIDE.md),
[attribute 정의](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Common/HciDecoderAttributes.cs),
[generator](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Generators/HciDecoderGenerator.cs),
[SampleVendorDecoder](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/tests/BluetoothKit.VendorContract.Tests/SampleVendorDecoder.cs).

## 5. 출력 형태: 주소, enum, 비트필드, 단위, 시간

핵심은 **필터와 export에 쓰이는 값의 타입**과 **사람에게 보여 주는 문자열**을 구분하는 것이다.
숫자를 모두 문자열로 바꾸면 범위 비교가 어려워진다. 주소도 주소 타입으로 등록한다.

| 원하는 출력 | 방법 | 필터 예시 |
|---|---|---|
| 10진수, 16진수, 두 표현 병기 | `base.DEC`, `HEX`, `HEX_DEC`, `DEC_HEX` | `bkv.handle == 0x1234` |
| enum 이름과 숫자 | uint ProtoField의 valuestring table | `bkv.status == 0` |
| true/false 및 의미 있는 문구 | `ProtoField.bool` + mask + true/false strings | `bkv.enabled == true` |
| 비트 그룹의 일부 숫자 | uint field + mask | `bkv.packed_count == 2` |
| BD_ADDR/MAC 형태 | `ProtoField.ether` + 올바른 순서의 Address 값 | `bkv.address == aa:bb:cc:dd:ee:ff` |
| IPv4/IPv6 | `ProtoField.ipv4` / `ipv6` | `bkv.ip == 192.168.1.2` |
| 부호 있는 RSSI | `ProtoField.int8` + 단위 text | `bkv.rssi < -40` |
| 원시 바이트 | `ProtoField.bytes` | `bkv.data == aa:bb:cc` |
| 길이가 정해진 문자열 | `ProtoField.string` + 명시적 인코딩 | `bkv.text contains "BT"` |
| 64-bit 정수 | `ProtoField.uint64` / `int64` | 정수 필드 비교 |
| 계산된 ms, 비율 등 | float/double field + `set_generated()` | `bkv.interval_ms > 5` |
| 절대/상대 시각 | `absolute_time` / `relative_time` + NSTime | 시간 타입으로 비교 |
| 다른 frame으로 이동 | `ProtoField.framenum` | 요청·응답 연결 필드 |

아래 코드 조각은 필요한 ProtoField를 파일 로드 시 `p.fields`에 등록한 상태를 전제로 한다.
완성 예제의 `f`는 해당 파일에서 쓰는 정의를 이미 포함한다.

### 5.1 enum: 이름을 보여 주되 값은 숫자로 유지

```lua
local status_names = {[0] = "Success", [1] = "Rejected", [2] = "Busy"}
local status_f = ProtoField.uint8("myvendor.status", "Status", base.HEX, status_names)

-- 패킷 안:
local r = tvb(offset, 1)
local status = r:uint() -- 분기는 실제 숫자로 한다.
t:add(status_f, r)     -- 화면: Success (0x00)
if status == 0 then
    -- 성공 layout 처리
end
```

enum table은 표시용 lookup이다. 등록되지 않은 숫자가 나왔다고 읽기에 실패하지 않는다.
그 값이 예약값인지, 향후 버전의 합법적인 값인지, 본문 layout이 달라지는지는 우리가 판단한다.
필터는 `myvendor.status == 0`처럼 숫자를 사용하면 enum label 변경이나 번역의 영향을 덜 받는다.

### 5.2 주소: BD_ADDR는 바이트 순서를 명시적으로 변환

현재 `HciValueFormatter.BdAddr()`는 wire의 6바이트를 뒤집어 출력한다.
예를 들어 `FF EE DD CC BB AA`는 `aa:bb:cc:dd:ee:ff`다.
**설치된 4.4.8에서 `t:add_le(ether_field, range)`는 이 순서 변환을 해 주지 않았다.**

```lua
local address_f = ProtoField.ether("myvendor.address", "BD_ADDR")

-- r은 경계 검사한 6-byte TvbRange.
local octets = {}
for i = 5, 0, -1 do
    octets[#octets + 1] = string.format("%02x", r(i, 1):uint())
end
local address = Address.ether(table.concat(octets, ":"))
t:add(address_f, r, address)
```

이 방식은 **주소 필드의 필터 기능과 원본 6바이트의 선택 표시를 함께 유지**한다.
이미 표시 순서로 전송되는 MAC 주소에는 역순 변환을 하지 않는다.
주소의 public/random 여부는 별도 Address Type 필드로 표시한다.
주소 값을 필드로 추가했다고 Packet List의 Source/Destination 컬럼이 자동 변경되지는 않는다.

IPv4/IPv6는 해당 타입에 맞는 range를 전달한다. 예를 들어 network order의
`C0 A8 01 02`를 `ProtoField.ipv4`로 추가하면 `192.168.1.2`가 된다.

### 5.3 비트필드: 추출용 값과 표시용 원본 range

SG의 `GroupSize=1, BitOffset=4, BitSize=4`는 다음 mask에 대응한다.

```lua
local flags_f = ProtoField.uint8("myvendor.flags", "Flags", base.HEX)
local enabled_f = ProtoField.bool("myvendor.enabled", "Enabled", 8,
    {"Enabled", "Disabled"}, 0x01)
local count_f = ProtoField.uint8("myvendor.count", "Count", base.DEC, nil, 0xF0)

local r = tvb(offset, 1)
local flags = t:add(flags_f, r)
flags:add(enabled_f, r)
flags:add(count_f, r)
local count = bit.rshift(bit.band(r:uint(), 0xF0), 4)
```

입력 `0x21`은 Enabled=true, Count=2다. mask가 있는 field에는 **추출 전 원본 range**를 전달한다.
이미 shift한 값을 mask field에 다시 넣으면 이중 추출이 될 수 있다.
SG의 `BitOffset`은 LE 정수의 LSB 기준이다. Lua `range:bitfield()`의 비트 번호는 MSB 기준이므로
SG 수치를 그대로 복사하지 않는다. LE 정수와 mask를 사용하는 편이 대응 관계가 분명하다.

2바이트 그룹이라면 uint16 field와 `add_le`, bool의 display 폭 `16`을 사용한다.
그룹 전체를 한 번 소비한 뒤 같은 range에 여러 하위 필드를 추가해야 한다.
하위 필드마다 offset을 더하면 안 된다.

### 5.4 숫자 단위와 계산값

```lua
local rssi_f = ProtoField.int8("myvendor.rssi", "RSSI", base.DEC)
t:add(rssi_f, rssi_range):append_text(" dBm")
```

`D6`는 `-42 dBm`으로 표시되지만 필터 값은 숫자 `-42`다.
`append_text()`는 표시만 바꾼다. `set_text()`도 필터 값 자체를 바꾸는 기능이 아니다.
특수값 127이 unavailable인 프로토콜이면 그 값에만 설명을 덧붙이고 실제 필드 값은 보존할 수 있다.

SG의 `Slot625`처럼 환산이 필요하면 원시값과 계산값을 함께 제공할 수 있다.

```lua
local slots_f = ProtoField.uint16("myvendor.slots", "Interval (slots)", base.DEC)
local ms_f = ProtoField.double("myvendor.interval_ms", "Interval (ms)")

t:add_le(slots_f, r)
t:add(ms_f, r:le_uint() * 0.625):set_generated()
```

입력 16 slots는 원시 필드 16과 계산 필드 10 ms가 된다.
`set_generated()`는 패킷에서 직접 읽은 필드가 아닌 파생 값임을 표시한다.
단위 문자열 자체가 타입 정의에 필요하면 `base.UNIT_STRING`도 제공된다.
값의 범위별 label에는 `base.RANGE_STRING`이 있지만, 단순 enum은 일반 valuestring이면 충분하다.

```lua
local duration_f = ProtoField.uint16("myvendor.duration_ms", "Duration",
    base.DEC + base.UNIT_STRING, {" ms", " ms"})
local quality_f = ProtoField.uint8("myvendor.quality", "Quality",
    base.DEC + base.RANGE_STRING, {{0, 9, "Low"}, {10, 99, "High"}})

-- 이미 읽은 값을 보여 주는 예; 실제 wire에서 읽을 때는 range를 전달한다.
t:add(duration_f, 16) -- Duration: 16 ms
t:add(quality_f, 23)  -- Quality: High (23)
```

unit table의 첫 문자열은 단수형, 둘째는 복수형이다. 표시할 공백도 문자열에 포함한다.
RSSI의 특수값 127만 enum table에 넣으면 일반적인 -42가 `Unknown (-42)`로 표시될 수 있다.
일반 숫자는 그대로 보여 주고 특수값만 설명하려면 조건부 `append_text()`가 간단하다.

### 5.5 문자열·바이트·정수 폭

```lua
-- UTF-8, length는 바이트 수.
t:add_packet_field(text_f, tvb(offset, length), ENC_UTF_8)

-- 구조를 모르는 데이터.
t:add(bytes_f, tvb(offset, length))

-- SG의 uint Size=3.
t:add_le(uint24_f, tvb(offset, 3))

-- SG의 ulong Size=6.
t:add_le(uint64_f, tvb(offset, 6))
local counter = tvb(offset, 6):le_uint64()
```

`stringz`는 NUL 종료 문자열에 사용한다. 종료 문자가 있다는 보장이 없으면 우선 bounded range 안에서
NUL을 찾거나 길이를 검사한다. 고정 배열의 ASCII/UTF-8과 NUL 종료 문자열은 다른 wire 규칙이다.
문자열의 글자 수와 UTF-8 바이트 수 역시 다르다.

`le_uint()`는 1~4바이트, `le_uint64()`는 1~8바이트용이다.
큰 64-bit 정수를 일반 Lua number로 무조건 변환하지 않는다.
Lua 버전별 숫자 표현 및 부호 범위 차이가 있고 double은 2^53을 넘는 모든 정수를 정확히 표현하지 못한다.
Wireshark의 UInt64/Int64 객체와 typed field를 유지하는 것이 안전하다.
관련 API는 [64-bit integers](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Int64.html)에 있다.

### 5.6 시각과 frame 참조

추가적인 표시 패턴은 다음과 같다. `seconds`, `nanoseconds`, `request_frame_number`는
wire spec 또는 요청·응답 연결 로직에서 이미 얻은 값이다.

```lua
local time_f = ProtoField.absolute_time("myvendor.time", "Device Time", base.UTC)
local duration_f = ProtoField.relative_time("myvendor.duration", "Duration")
local request_f = ProtoField.framenum("myvendor.request_in", "Request in frame",
    base.NONE, frametype.REQUEST)

t:add(time_f, NSTime(seconds, nanoseconds)):set_generated()
t:add(duration_f, NSTime(0, 1250000)):set_generated() -- 1.25 ms
t:add(request_f, request_frame_number):set_generated()
```

장치 tick을 Unix epoch 초로 해석하면 안 된다. epoch·tick 주기·wrap 규칙을 먼저 확인한다.
framenum 필드는 연결을 표시할 뿐 요청 frame을 자동으로 찾지 않는다.

필드 타입·enum·mask는 [ProtoField API](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html),
표시 문자열·generated·expert 추가는 [Tree API](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html)를 참고한다.

## 6. 레이아웃별 예제

이 절의 `c`는 완성 파일의 작은 cursor다.
`c:u(field, n, label)`은 LE unsigned integer를 읽고 표시하며 n바이트 진행한다.
`c:bytes(...)`는 정확히 n바이트, `c:take(...)`는 표시 없이 range를 소비한다.
`entry(c, i, name, parser)`는 subtree를 만들고 parser 실행 후 실제 소비 길이를 설정한다.
범위 검사 구현은 7절에서 설명한다.

### 6.1 필드 값에 따른 decoder 분기: tagged union

가상 wire format:

```text
Action:u8
  0 → body 없음
  1 → BD_ADDR:6 bytes
  2 → Handle:u16le
  그 외 → body layout 모름
```

```lua
local action = c:u(f.action, 1, "Action")
if action == 0 then
    -- 본문 없음
elseif action == 1 then
    bd_addr(c)
elseif action == 2 then
    c:u(f.handle, 2, "Handle")
else
    c:unknown("Unknown action")
end
```

본문 종류가 많으면 조건문 대신 함수 테이블을 쓴다.

```lua
local decoders = {
    [0x10] = decode_status,
    [0x20] = decode_reports,
    [0x30] = decode_trace
}
local decode = decoders[message_id]
if decode then decode(c) else c:unknown("Unknown message") end
```

함수들을 먼저 선언하고 이 테이블을 만든다. 없는 branch를 추정해 파싱하지 않는다.
Status가 성공일 때만 본문이 존재하는 프로토콜이라면 같은 패턴으로 처리할 수 있다.
**Status != 0이면 나머지 필드가 없다는 규칙은 각 메시지 spec에서 확인해야 한다.**
기존 SG가 항상 읽던 필드를 status만 보고 생략하는 것은 의미 변경이다.

### 6.2 조건에 따라 필드 자체가 존재: flags + optional field

```lua
local flags = c:u(f.flags, 1, "Flags")
if bit.band(flags, 0x01) ~= 0 then
    c:u(f.handle, 2, "Optional Handle")
end
-- 다음 필드는 optional handle이 있을 때만 2바이트 뒤에서 시작한다.
```

표시만 숨기는 것이 아니라 실제 소비 길이가 바뀐다.
버전별 확장 필드도 `if version >= 2 then ... end`로 표현할 수 있지만,
미래 버전까지 같은 크기라고 보장되지 않으면 지원 버전을 명시적으로 분기한다.

### 6.3 필드 값으로 길이가 정해지는 bytes

SG:

```csharp
[HciField] public byte DataLength { get; }
[HciField(CountFrom = nameof(DataLength))]
public ReadOnlyMemory<byte> Data { get; }
[HciField] public sbyte Rssi { get; }
```

Lua:

```lua
local length = c:u(f.length, 1, "Data Length")
c:bytes(f.data, length, "Data")
rssi(c)
```

`03 AA BB CC D6`에서는 Data가 3바이트이고 그 다음 RSSI는 -42다.
길이가 0이어도 RSSI는 이어서 존재한다.
`Data`를 남은 전체 range로 읽으면 RSSI까지 먹어버린다.
현재 [LeAdvertisingReportEntry](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Decoder/Events/LeMeta/Subevents.cs)도
`DataLength → Data → Rssi` 형태이므로 이 경계가 실제로 중요하다.

Length의 의미는 먼저 표로 고정한다: 바이트 수인가, 원소 수인가, 자기 자신이나 헤더를 포함하는가,
padding을 포함하는가. 예를 들어 ushort 3개의 count는 3이고 소비 바이트는 6이다.

### 6.4 고정 크기 구조체 배열

```text
Count:u8
Records[Count] = { Handle:u16le, RSSI:i8 }  // entry당 3 bytes
```

```lua
local function decode_record(e)
    e:u(f.handle, 2, "Handle")
    rssi(e)
end
local count = c:u(f.count, 1, "Count")
for i = 0, count - 1 do
    entry(c, i, "Record", decode_record)
end
```

화면에는 Record[0], Record[1] subtree가 생긴다. 모든 원소가 같은 `bkv.handle`,
`bkv.rssi` field 정의를 반복 사용한다. 원소마다 새로운 ProtoField를 만들지 않는다.
메모리상 C# struct 크기나 alignment가 아니라 **wire field 크기의 합**이 stride다.

고정 크기라면 `count <= floor(remaining / entry_size)`를 미리 검사할 수도 있다.
완성 예제는 원소·필드별 검사로 진행해 뒤쪽 원소가 짧을 때 앞에서 읽은 필드를 유지한다.

프로젝트 [ReadLocalSupportedCodecsV2Event](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Decoder/Events/CommandComplete/InformationalParameters.cs)는
`StandardCodecEntry` 2바이트 배열 뒤에 또 다른 count와 `VendorSpecificCodecEntry` 5바이트 배열이 온다.
두 배열의 count와 시작 위치를 각각 읽어야 한다. 전체를 동일 stride로 순회할 수 없다.

### 6.5 고정 원소 개수와 scalar 배열

```csharp
[HciField(Count = 5)]
public ReadOnlyMemory<ushort> Values { get; }
```

```lua
for i = 1, 5 do
    c:u(f.value, 2, "Value")
end
```

총 10바이트를 읽는다. `ReadOnlyMemory<byte>`는 bytes 하나로 표시할 수도 있고,
원소별 숫자 필터가 필요하면 uint8을 반복 추가할 수도 있다.
구조체 배열에서도 CountFrom 대신 상수 반복 횟수를 사용하면 된다.

### 6.6 가변 크기 구조체의 배열: 실제 CsStepEntry 대응

현재 [CsStepEntry](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Decoder/Events/LeMeta/ChannelSounding.cs)는:

```csharp
[HciStruct]
public readonly partial struct CsStepEntry
{
    [HciField("Step Mode")] public byte StepMode { get; }
    [HciField("Step Channel")] public byte StepChannel { get; }
    [HciField("Step Data Length")] public byte StepDataLength { get; }
    [HciField("Step Data", CountFrom = nameof(StepDataLength))]
    public ReadOnlyMemory<byte> StepData { get; }
}
```

상위의 `NumStepsReported`가 entry 수를 결정한다. Lua에서는:

```lua
local function decode_step(e)
    e:u(f.mode, 1, "Step Mode")
    e:u(f.channel, 1, "Step Channel")
    local n = e:u(f.step_length, 1, "Step Data Length")
    e:bytes(f.step_data, n, "Step Data")
end

local count = c:u(f.count, 1, "Num Steps Reported")
for i = 0, count - 1 do
    entry(c, i, "Step", decode_step)
end
```

```text
02 | 01 25 02 AA BB | 02 26 03 10 20 30
│    └─ Step[0]: 5 bytes
│                      └─ Step[1]: 6 bytes
└─ count=2
```

두 번째 원소의 시작점은 첫 번째 원소를 실제로 해석한 뒤에 결정된다.
`base + i * sizeof(struct)` 같은 계산으로 접근할 수 없다.
현재 프로젝트는 StepData를 raw로 내보낸다. 완성 예제도 이 의미를 유지한다.
StepMode별 세부 디코더를 추가할 때는 아래 TLV와 같은 bounded child parser를 사용하고
각 mode의 실제 wire spec을 별도로 확보한다.

### 6.7 StructArg: 상위 값이 하위 구조 해석을 결정

현재 SG의 예:

```csharp
[HciField("Scanning PHY Parameters", StructArg = nameof(ScanningPhys))]
public ScanningPhyParams ScanningPhyParams { get; private set; }
```

[ScanningPhyParams](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Decoder/Commands/LeController.cs)는
set bit를 순서대로 돌며 entry를 읽는 수동 wrapper다. Lua에서는 일반 함수 인수로 표현한다.

```lua
local function decode_phy_params(c, phys)
    for _, bit_index in ipairs({0, 2}) do
        if bit.band(phys, 2 ^ bit_index) ~= 0 then
            entry(c, bit_index, "PHY", function(e)
                e:u(f.scan_type, 1, "Scan Type")
                e:u(f.interval, 2, "Scan Interval")
                e:u(f.window, 2, "Scan Window")
            end)
        end
    end
end
local phys = c:u(f.phys, 1, "Scanning PHYs")
decode_phy_params(c, phys)
```

`phys=0x05`는 5개 entry가 아니라 bit 0과 bit 2에 해당하는 **2개 entry**다.
원소 순서는 wire spec의 bit 순서에 따른다. 완성 예제는 지원하지 않는 bit가 있으면 raw로 남긴다.
현재 C# wrapper는 모든 set bit를 순회하므로, 실제 이관에서는 지원 bit 정책을 의도적으로 결정한다.

`LmpFeatures`의 `StructArg = nameof(PageNumber)`도
`decode_lmp_features(c, page_number)`로 대응한다. 같은 8바이트를 소비하되 page별로 다른 mask·이름을
표시할 수 있다. 알려지지 않은 page도 크기가 고정이라면 raw 8바이트를 보존하고 다음 필드를 읽을 수 있다.

배열 원소도 `decode_entry(c, version, mode)`처럼 context를 받을 수 있다.
`[HciStruct]`에 대응하는 하위 함수는 **상위 전체 버퍼의 끝인지 검사하지 않는다**.
전체 종료 검사는 상위 parser, 길이가 별도로 정해진 child block 종료 검사는 그 child parser가 담당한다.

### 6.8 비트필드에서 count를 얻는 배열

SG 가이드의 `BitOffset=4, BitSize=4` Count와 대응한다.

```lua
local raw = c:take(1, "Flags"):uint()
local count = bit.rshift(bit.band(raw, 0xF0), 4)
for i = 1, count do
    c:u(f.value, 2, "Value")
end
```

입력 `0x20`이면 ushort 두 개로 4바이트를 소비한다.
완성 예제 case 8은 bit 0으로 optional Handle의 존재도 결정한다.

### 6.9 TLV: 길이로 경계를 분리하고 type으로 분기

```text
반복: Type:u8, Length:u8, Value[Length]
Type 1 → uint16le
Type 2 → UTF-8 string
Type 3 → BD_ADDR
기타   → raw, Length만큼 건너뛰기
```

```lua
local kind = c:u(f.tlv_type, 1, "TLV Type")
local n = c:u(f.length, 1, "TLV Length")
local value_range = c:take(n, "TLV Value")
local child = cursor(value_range:tvb(), c.tree, 0, n)

if kind == 1 then
    child:u(f.value, 2, "Value")
elseif kind == 2 then
    child.tree:add_packet_field(f.text, child:take(n, "Text"), ENC_UTF_8)
elseif kind == 3 then
    bd_addr(child)
else
    child:unknown("Unknown TLV")
end
child:finish()
```

type 1인데 Length=1 또는 3이면 오류다. 길이가 1일 때 다음 TLV의 첫 바이트를
값의 두 번째 바이트로 가져오면 안 된다. child buffer를 분리하면 그 실수를 방지할 수 있다.
unknown type도 Length가 알려져 있으므로 건너뛰고 다음 TLV를 계속 해석할 수 있다.
Length=0을 허용한다면 반복이 header 2바이트만큼은 반드시 진행해야 한다.

반면 길이 정보가 없는 unknown union에서는 다음 필드의 시작점을 알 수 없으므로
남은 본문을 raw로 보존하고 해당 본문의 해석을 끝내는 것이 적절하다.

### 6.10 중첩 구조체와 길이 단위

구조체 안에 다른 구조체나 배열이 있어도 함수 호출을 중첩하면 된다.

```lua
local function decode_group(c, version)
    local count = c:u(f.count, 1, "Record Count")
    for i = 0, count - 1 do
        entry(c, i, "Record", function(e)
            decode_record_for_version(e, version)
        end)
    end
end
```

상위 Length가 group 전체 바이트 수라면 TLV처럼 group 전용 bounded cursor를 만들고
그 안에서 Count개를 읽은 뒤 정확히 끝났는지 검사한다.
Count와 Length는 서로 대체되지 않는다. 둘이 일치해야 한다는 규칙은 별도로 검증한다.

wire가 alignment padding을 정의했다면 group의 기준 offset을 기준으로
`padding = (alignment - ((offset - group_start) % alignment)) % alignment`를 계산해 소비한다.
C/C#의 메모리 구조체 alignment를 근거로 padding을 추가하지 않는다.

### 6.11 남은 bytes, 빈 본문, 외부 dissector 호출

```lua
-- SG의 Size/Count/CountFrom 없는 마지막 ReadOnlyMemory<byte>.
c:bytes(f.raw, c.limit - c.off, "Remaining Data")

-- 파라미터가 없는 메시지는 본문을 읽지 않고 finish()만 호출한다.
```

여기서 remaining의 끝은 캡처 전체가 아니라 **현재 메시지/child block의 끝**이다.
모든 디코더 끝에 raw remaining을 붙여 길이 불일치를 숨기지 않는다.
확장 영역이 허용된 메시지에만 사용한다.

본문 일부가 기존 Wireshark 프로토콜이면 재사용도 가능하다.

```lua
-- 파일 로드 시:
local data_dissector = Dissector.get("data")

-- dissector 안, 정확한 payload range를 확보한 뒤:
data_dissector:call(payload_range:tvb(), pinfo, subtree)
```

알려진 AD 등의 parser도 같은 형태로 호출할 수 있지만, 해당 C dissector가
별도의 data/context 인수를 요구하는지 소스에서 확인한다. Lua의 `call(tvb,pinfo,tree)`로
임의의 C context 구조체를 넘길 수 있는 것은 아니다. 등록된 이름도 먼저 확인한다.

## 7. malformed 처리는 얼마나 직접 해야 하는가

**BluetoothKit의 `HciDecodeResult`, partial typed model, 실패 field snapshot을 다시 구현할 필요는 없다.**
Wireshark는 바이트 접근의 범위를 검사하고, 상세 트리를 보유하며, 오류 표시와 Expert Info UI를 제공한다.
성공한 필드를 먼저 트리에 추가했다면 이후 오류 때문에 별도의 prefix 모델을 만들 필요도 없다.

다만 “Wireshark가 예외를 처리한다”와 “우리 프로토콜의 모든 오류를 정확히 진단한다”는 서로 다른 기능이다.

### 직접 재현한 차이

4바이트 버퍼에서 `tvb(0, 999)`를 실행한 결과:

```text
_ws.lua.error = 1
_ws.malformed = (없음)
Lua Error: ... Range is out of bounds
```

따라서 Lua에서 범위를 넘겨 읽는 것을 일반적인 malformed 표시 수단으로 권장하지 않는다.
설치된 4.4.8에서는 Lua Error가 Error/Undecoded로 표시되었고,
전달받은 master 소스는 `_ws.lua.error`를 PI_DISSECTOR_BUG로 등록한다.
버전별 group 이름의 차이와 무관하게, 프로토콜을 설명하는 진단 대신 Lua 실행 오류가 된다는 점이 핵심이다.

소스 근거:

- `epan/wslua/wslua_tvb.c`: `push_TvbRange()`는 captured length를 넘어서는 range에 `luaL_error()`를 낸다.
- 같은 파일 상단 주석: C tvbuff 예외 처리와 Lua range 사전 검사의 차이를 설명한다.
- `epan/wslua/init_wslua.c`: Lua 오류 handler가 `_ws.lua.error` Expert Info를 추가한다.

### 책임 구분

| 상황 | 처리 주체와 정책 |
|---|---|
| btsnoop 레코드 읽기, H4·표준 HCI 헤더 | 기존 Wireshark reader/상위 dissector가 담당 |
| Lua의 잘못된 범위 접근 | Wireshark가 오류를 검출하지만 Lua Error가 될 수 있음 |
| vendor Length가 외부 block을 넘음 | 우리 parser가 검사하고 malformed expert 추가 |
| 원소 count와 실제 본문 크기가 모순 | 우리 parser가 검사 |
| scan window > interval 같은 의미 규칙 | Wireshark가 추론할 수 없으므로 우리 parser가 검사 |
| unknown opcode/message/version | 지원하지 않는 레이아웃. unknown/raw 표시, 그 자체로 malformed는 아님 |
| snaplen 등으로 캡처된 바이트만 부족 | captured/reported를 근거로 truncated 진단 |
| 이미 읽은 prefix 표시 | TreeItem에 이미 추가한 필드를 사용 |
| trailing bytes | 프로토콜의 확장·padding·엄격 소비 정책에 맞춰 결정 |

표준 HCI header를 중복 구현할 필요는 없지만, vendor parser가 사용하는 **본문 경계는 정의해야 한다**.
완성 예제의 adapter는 offset과 선언된 끝을 만들기 위해 HCI length를 읽고 일관성을 확인한다.

### 세 가지 길이를 구분

```text
captured length : 파일에 실제로 남아 있는 바이트 수
reported length : 캡처 메타데이터가 보고한 원래 바이트 수
declared length : 프로토콜 Length 필드가 선언한 메시지/child block 길이
```

원하는 끝 offset이 declared boundary를 넘으면 layout 오류다.
declared boundary 안이지만 captured boundary를 넘고 reported boundary 안이면 캡처가 잘린 것으로
진단할 수 있다. reported metadata 자체가 잘림 정보를 보존하지 않았다면 둘을 확정적으로 구분할 수 없다.
큰 Length를 `math.min(length, remaining)`으로 줄여 정상 데이터처럼 표시하지 않는다.

### 작은 공통 검사 함수로 충분한 이유

완성 예제의 `take()`는 다음 순서로 검사한다.

```lua
if requested_length > declared_end - offset then
    -- Invalid vendor length / malformed
elseif requested_length > tvb:captured_len() - offset then
    -- reported length를 함께 확인하여 truncated 또는 malformed
else
    local r = tvb(offset, requested_length)
    -- 소비 후 반환
end
```

이 예상 가능한 입력 오류만 private marker가 있는 Lua table로 전달하고 최상위 `pcall`에서
`tree:add_proto_expert_info()`로 바꾼다. field마다 `if not ... then return ...`를 반복하지 않기 위한
작은 편의 장치이며 필수 아키텍처는 아니다. `nil, error`를 반환하는 스타일로 작성해도 된다.

**모든 Lua 예외를 malformed로 바꾸지 않는다.** 잘못된 API 호출, nil 참조, 등록 실수는 코드 버그다.
예제도 자신의 입력 오류 marker가 없으면 재throw해 Wireshark의 Lua Error로 드러낸다.
진짜 프로토콜 필드마다 failure DTO나 별도의 success model을 만들지 않는다.

배열에서 이미 완료된 entry는 유지된다. 진행 중 entry의 일부 필드도 표시될 수 있다.
이는 기존 SG가 어느 단위까지 prefix를 확정하느냐와 완전히 같을 필요는 없다.
기존 CLI/MCP의 JSON 계약까지 유지해야 한다면 그 요구는 별도 export adapter에서 다룬다.

### 재조립은 별개의 문제

btsnoop HCI 메시지의 잘린 바이트가 다음 frame에 있다는 보장은 없다.
따라서 단순 길이 부족에 TCP의 `pinfo.desegment_len`을 사용하면 안 된다.
vendor 프로토콜이 여러 event에 걸쳐 fragment를 정의한다면 transaction ID, 순서, 총 길이,
adapter/direction 등을 기준으로 별도의 재조립이 필요하다.

실제로 TCP 위의 길이 기반 프로토콜을 작성할 때는 `dissect_tcp_pdus()`로 TCP segmentation과
coalescing을 처리할 수 있다. HCI용 경계 검사와 혼동하지 않는다.

## 8. 필터, 출력, 재분석과 마이그레이션

### 필터와 export

예제의 필터:

```text
bkv
bkv.route == 0xa0 && bkv.message_id == 1
bkv.address == aa:bb:cc:dd:ee:ff
bkv.rssi < -40
bkv.packed_count == 2
bkv.malformed || bkv.truncated
_ws.lua.error
```

TShark로 값만 출력:

```sh
/Applications/Wireshark.app/Contents/MacOS/tshark \
  -n -r /tmp/bkv.btsnoop \
  -X lua_script:vendor_hci/init.lua \
  -d bthci_cmd.vendor=bkv -Y bkv \
  -T fields -E header=y -E occurrence=a \
  -e frame.number -e bkv.address -e bkv.rssi \
  -e bkv.step.mode -e bkv.step.data -e bkv.malformed
```

상세 구조가 필요하면 같은 명령의 출력 옵션을 다음으로 변경한다.

```sh
-T pdml
```

JSON 출력은 다음 옵션을 사용한다.

```sh
-T json --no-duplicate-keys
```

`-T fields`는 같은 필드의 여러 출현을 평탄화한다.
어떤 Handle과 RSSI가 같은 entry에 속하는지까지 보장하지 않는다.
`bkv.handle == X && bkv.rssi < Y`도 서로 다른 entry가 각각 조건을 만족할 수 있다.
entry 단위 처리에는 PDML 등의 subtree 구조를 사용하고, JSON에서도 필요한 구조가 보존되는지
실제 출력으로 확인한다. Wireshark의 JSON이 기존 `HciDecodeResult` JSON과 같은 계약은 아니다.

4.4.8의 native Vendor Event 분기는 Lua가 성공해도 `Event undecoded` Note를 추가했다.
이 Note만으로 Lua decoder 실패를 판단하지 않는다. `bkv.malformed`, `bkv.truncated`,
`_ws.lua.error`와 실제로 추가된 필드를 확인한다.

### 같은 패킷이 여러 번 분석될 수 있다

표시 필터 변경이나 재분석으로 dissector가 다시 호출되는 것을 전제로 한다.
패킷 하나로 해석이 끝나는 decoder는 호출될 때마다 같은 tree를 생성하면 된다.

상태를 관리할 때는 `pinfo.visited`를 사용해 중복 갱신을 방지한다.

```lua
local state = {}
function p.init()
    state = {}
end

-- dissector 안의 개념 예:
if not pinfo.visited then
    -- frame 번호나 transaction 키를 사용해 상태를 한 번 갱신한다.
end
-- visited여도 필요한 필드를 다시 tree에 추가한다.
```

`if pinfo.visited then return end`로 일반적인 tree 생성까지 중단하지 않는다.
`Tvb`, `TvbRange`, `TreeItem`을 다음 호출까지 보관하지 않는다.
필요하면 숫자나 복사한 bytes를 보관하고 capture를 닫으면 해제한다.
여러 adapter·방향·transaction ID의 충돌과 메모리 사용량도 고려한다.
callback과 visited의 상세 설명은 [Pinfo API](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html)에 있다.

### 검증 결과와 예제 목록

`make_examples.py --check ...`로 다음을 확인했다.

- **28 frame**의 기대 필드 값과 unknown/malformed/truncated 분류.
- 일반 읽기와 `tshark -2`의 필드 출력 일치.
- 정상·unknown 계열 샘플의 **208개 바이트 경계**에서 캡처를 잘라도 Lua Error가 발생하지 않는 것.
- BD_ADDR 역순 변환, enum, 음수 RSSI, 6-byte 정수, 계산한 ms, UTF-8, mask count 표시.

| frame | 확인할 내용 |
|---:|---|
| 1–3 | 현재 SampleVendorContract의 Command/Subevent/Message |
| 4–5 | Command Complete의 미정의 반환 형식, Command Status의 표준 구조 |
| 6 | enum, 주소, 24/48bit 값, RSSI, ms, IPv4, 문자열 |
| 7–10 | Action에 따른 union 분기, unknown branch |
| 11–12 | 동적 bytes 길이와 후속 RSSI, length=0 |
| 13 | 고정 크기 구조체의 가변 개수 배열 + ushort 고정 5개 |
| 14–15 | CsStepEntry 가변 크기 배열, count=0 |
| 16 | TLV의 known/unknown/zero length와 다음 TLV로의 진행 |
| 17 | StructArg에 대응하는 PHY mask |
| 18–19 | bitfield count와 optional field |
| 20–27 | unknown route, 짧은 필드, 여분 bytes, 길이 모순, 의미상 모순 |
| 28 | reported > captured인 캡처 잘림 |

합성 입력에 대한 검증이며, 접근할 수 없는 vendor 구현과의 호환성은 아직 확인하지 못했다.
실제 wire spec에서 만든 golden packet으로 예제를 교체하고 추가한다.

### 기존 vendor decoder를 확보한 뒤의 순서

1. **route 표를 추출한다.** Command opcode, CC opcode, Event subevent/message ID를 정리하고,
   decoder가 받는 시점에 이미 소비된 header를 기록한다.
2. **wire schema를 표로 만든다.** 필드 순서, 타입, endian, length/count 단위, selector,
   조건부 필드, padding, 허용하는 trailing bytes를 정리한다. 수동 TryDecode도 포함한다.
3. **출력 타입을 정한다.** 안정적인 filter 이름, enum, address, 원시값과 환산값을 정의한다.
   표시 이름과 filter 이름을 구분한다.
4. **본문 parser를 옮긴다.** scalar → fixed bytes → counted array → contextual struct → union/TLV 순으로
   SG 속성과 수동 처리의 의미를 옮긴다. HCI adapter는 한곳에 모은다.
5. **unknown/invalid/truncated 정책을 정한다.** SG의 failure 타입을 다시 구현할 필요는 없다.
   필요한 경계 검사와 의미 검사를 Expert Info로 표현한다.
6. **같은 원시 바이트로 비교한다.** enum 표시뿐 아니라 숫자, 배열 대응, 남은 bytes,
   malformed 위치도 비교한다. 주소 순서와 단위 차이를 우선 확인한다.
7. **실제 로그에서 진입점을 확인한다.** btsnoop encapsulation, Company ID 인식 여부,
   vendor table 충돌, CC/CS, 여러 adapter, 재분석을 확인한다.
8. **사용 방법을 함께 배포한다.** Lua package, 지원 Wireshark/Lua 버전, Decode As 또는 자동 등록 방법,
   fixtures와 검증 명령을 묶는다.

규모가 커지면 `init.lua / fields.lua / reader.lua / commands.lua / events.lua / structs.lua` 정도로
나눌 수 있다. `init.lua`에서 fields와 helper를 먼저 로드하고 마지막에 dissector를 등록한다.
route table과 field 선언은 코드 생성에도 적합하지만, 처음부터 SG 규모의 generator를 만들 필요는 없다.
수동 구현으로 wire와 출력 계약을 확정한 다음 반복되는 정의만 생성하면 적절한 범위를 판단하기 쉽다.

Lua plugin을 로드하면 Wireshark/TShark가 확장된다.
기존 BluetoothKit CLI/MCP의 decode에 자동으로 반영되지는 않는다.
이들도 같은 결과를 사용하려면 TShark 호출, 출력 변환, 배포 의존 관계를 별도로 설계해야 한다.

## 9. 작성자에 따라 구현이 얼마나 달라지는가

**같은 wire 명세와 같은 출력 계약을 따르면, 정상 패킷을 읽는 핵심 코드는 상당히 비슷해진다.**
필드 순서·폭·endian은 명세로 정해져 있고, 배열은 반복하며 selector에 따라 분기한다.
Wireshark가 등록 API, typed field, tree, 표시와 필터 기능을 제공하므로 이 부분의 자유도도 제한적이다.
이는 위 API와 예제를 바탕으로 한 구현상의 판단이며, 모든 dissector가 동등하다는 보장은 아니다.

예를 들어 같은 `Count:u8 + Entries[Count]`를 구현한다면 작성자마다 달라지는 부분은
수동 `offset`을 쓸지 cursor를 쓸지, `if`를 쓸지 함수 table을 쓸지 정도일 수 있다.
공통 요구사항을 만족한다면 이런 코드 구성의 차이가 해석 결과의 차이로 이어질 필요는 없다.

| 영역 | 구현에서 달라질 수 있는 부분 | 실제 영향 |
|---|---|---|
| 정상 본문 파싱 | offset/cursor, 함수 분리, 선언형 schema 사용 | 주로 가독성과 유지보수 |
| 경계·오류 처리 | 선언 길이 준수, 잘림 분류, 부분 필드 유지, unknown 처리 | 같은 비정상 입력에서 결과가 달라질 수 있음 |
| 필드·출력 계약 | 숫자와 문자열 타입, 필터 이름, 주소 순서, 단위, 배열 subtree | 필터·JSON·후속 도구의 사용성과 호환성 |
| 버전·확장 처리 | unknown TLV 건너뛰기, trailing bytes 허용 여부, 버전별 layout | 새 firmware 데이터의 해석 범위 |
| 등록과 식별 | Decode As, Company ID, protocol 식별 조건 | 어떤 패킷에 decoder가 호출되는지 |
| 상태·재조립 | transaction 키, fragment 관리, 재분석 시 상태 갱신 | 여러 패킷에 걸친 해석의 정확성 |
| 실행 비용 | 반복 lookup, bytes 복사, 상태 보관량 | 큰 캡처에서 시간·메모리 차이 |

가령 `Length=4`인데 body가 2바이트인 입력에서 어떤 구현은 범위 오류로 중단하고,
어떤 구현은 2바이트로 줄여 정상처럼 표시하며, 다른 구현은 길이 모순을 명시할 수 있다.
정상 입력에서 같아 보이는 세 구현도 이 입력에 대한 의미는 다르다.
주소를 문자열로 만드는 구현과 `ProtoField.ether`로 만드는 구현 역시 화면은 비슷할 수 있지만
필드 타입과 사용할 수 있는 필터는 달라진다.

우리처럼 기존 decoder와 명세를 옮기는 작업에서는 메시지별로 새로운 알고리즘을 고안하기보다,
**다음 공통 규칙을 먼저 정하고 payload parser를 일관되게 작성하는 정도가 적절하다.**

1. HCI 진입점이 넘기는 본문 범위와 route/context의 형태.
2. filter 이름·타입·enum·주소 순서·환산 단위 규칙.
3. 경계 검사와 unknown/malformed/truncated, trailing bytes 정책.
4. 구조체 함수와 배열 subtree를 만드는 방식.
5. 같은 fixture에서 기대하는 값·출력 구조·오류 분류.

큰 framework는 필수가 아니다. 이 예제의 cursor와 marker/pcall도 구현 선택 중 하나다.
동일한 경계 규칙을 지키는 명시적인 검사와 조기 반환 방식으로 작성해도 된다.
fragment나 요청·응답 상태가 없는 메시지는 패킷별 parser만으로 충분하다.

## 10. 참고자료와 전체 URL

앞서 설명과 본문에서 언급한 외부 링크를 주소까지 확인할 수 있도록 모았다.
온라인 API 문서는 갱신될 수 있으므로 설치한 Wireshark 버전의 지원 여부와 함께 확인한다.
`wireshark-4.4.8` 링크는 설치 바이너리와 맞춘 소스이며 `master` 링크는 변경될 수 있다.

### 공식 문서

| 자료 | 전체 URL | 참고할 내용 |
|---|---|---|
| [Wireshark Developer’s Guide](https://www.wireshark.org/docs/wsdg_html/) | `https://www.wireshark.org/docs/wsdg_html/` | 개발자 문서 전체 |
| [Lua 지원과 로딩](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html) | `https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html` | 스크립트 로드, `-X lua_script`, 패키지와 `init.lua` |
| [Proto / ProtoField / ProtoExpert / DissectorTable](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html) | `https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html` | 등록, enum·mask·field 타입, Expert Info, 하위 dissector, TCP PDU 처리 |
| [Tvb / TvbRange / ByteArray](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html) | `https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tvb.html` | 범위, captured/reported 길이, endian별 값 읽기 |
| [TreeItem](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html) | `https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html` | `add`, `add_le`, `add_packet_field`, generated·expert·표시 문자열 |
| [Field / FieldInfo](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Field.html) | `https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Field.html` | 상위 dissector가 만든 필드 참조 |
| [Pinfo](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html) | `https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Pinfo.html` | frame 정보, 컬럼, visited, 재조립 관련 속성 |
| [Int64 / UInt64](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Int64.html) | `https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Int64.html` | 큰 정수를 정확히 보관하고 연산하는 방법 |
| [Plugin folders](https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html) | `https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html` | 플러그인 설치 폴더 |

### HCI와 Lua 구현 소스

| 자료 | 전체 URL | 참고할 내용 |
|---|---|---|
| [4.4.8 HCI Command](https://github.com/wireshark/wireshark/blob/wireshark-4.4.8/epan/dissectors/packet-bthci_cmd.c) | `https://github.com/wireshark/wireshark/blob/wireshark-4.4.8/epan/dissectors/packet-bthci_cmd.c` | 설치 버전의 vendor hook과 등록 |
| [4.4.8 HCI Event](https://github.com/wireshark/wireshark/blob/wireshark-4.4.8/epan/dissectors/packet-bthci_evt.c) | `https://github.com/wireshark/wireshark/blob/wireshark-4.4.8/epan/dissectors/packet-bthci_evt.c` | 설치 버전의 CC/CS/vendor event 호출 경로 |
| [master HCI Command](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-bthci_cmd.c) | `https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-bthci_cmd.c` | 로컬 소스와 대조할 Command 구현 |
| [master HCI Event](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-bthci_evt.c) | `https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-bthci_evt.c` | 로컬 소스와 대조할 Event 구현 |
| [master Lua Tvb](https://github.com/wireshark/wireshark/blob/master/epan/wslua/wslua_tvb.c) | `https://github.com/wireshark/wireshark/blob/master/epan/wslua/wslua_tvb.c` | `push_TvbRange`, 범위 검사와 Lua 오류 |
| [master Lua 초기화·호출](https://github.com/wireshark/wireshark/blob/master/epan/wslua/init_wslua.c) | `https://github.com/wireshark/wireshark/blob/master/epan/wslua/init_wslua.c` | Lua Error handler와 Expert Info 등록 |
| [master Lua 필드 정의](https://github.com/wireshark/wireshark/blob/master/epan/wslua/wslua_proto_field.c) | `https://github.com/wireshark/wireshark/blob/master/epan/wslua/wslua_proto_field.c` | field 타입, valuestring, unit·range string |
| [master Lua tree](https://github.com/wireshark/wireshark/blob/master/epan/wslua/wslua_tree.c) | `https://github.com/wireshark/wireshark/blob/master/epan/wslua/wslua_tree.c` | typed field 추가와 값·인코딩 처리 |

로컬에서 직접 읽은 소스 루트는 `/Users/kihunahn/Downloads/wireshark-master`다.
위 master URL은 같은 파일의 공개 경로이며, 로컬 snapshot과 같은 revision이라는 뜻은 아니다.
BluetoothKit SG와 모델은 아래 revision 고정 링크로 참조한다. 해당 레포지토리 접근 권한이 필요할 수 있다.

### BluetoothKit SG와 모델

참조 revision: `b90bd23ac3de8d99a0226ebb67be66276c5f3773`.

| 자료 | 전체 URL |
|---|---|
| [SG 작성 가이드](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/docs/HCI_DECODER_AUTHORING_GUIDE.md) | `https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/docs/HCI_DECODER_AUTHORING_GUIDE.md` |
| [attribute 정의](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Common/HciDecoderAttributes.cs) | `https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Common/HciDecoderAttributes.cs` |
| [generator](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Generators/HciDecoderGenerator.cs) | `https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Generators/HciDecoderGenerator.cs` |
| [SampleVendorDecoder](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/tests/BluetoothKit.VendorContract.Tests/SampleVendorDecoder.cs) | `https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/tests/BluetoothKit.VendorContract.Tests/SampleVendorDecoder.cs` |
| [LeAdvertisingReportEntry](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Decoder/Events/LeMeta/Subevents.cs) | `https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Decoder/Events/LeMeta/Subevents.cs` |
| [ReadLocalSupportedCodecsV2Event](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Decoder/Events/CommandComplete/InformationalParameters.cs) | `https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Decoder/Events/CommandComplete/InformationalParameters.cs` |
| [CsStepEntry](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Decoder/Events/LeMeta/ChannelSounding.cs) | `https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Decoder/Events/LeMeta/ChannelSounding.cs` |
| [ScanningPhyParams](https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Decoder/Commands/LeController.cs) | `https://github.com/szcpsta/BluetoothKit/blob/b90bd23ac3de8d99a0226ebb67be66276c5f3773/src/BluetoothKit.Core/LogTypes/BtSnoop/Decoder/Commands/LeController.cs` |

### 이 레포지토리의 패키지 구성

[README](../README.md)에 설치·실행·구조를 정리했다. Wireshark의 모듈 로딩 권장 방식은
[공식 shared modules 예제](https://www.wireshark.org/docs/wsdg_html_chunked/wslua_require_example.html)를 참고한다.

전체 URL: `https://www.wireshark.org/docs/wsdg_html_chunked/wslua_require_example.html`
