# vendor_hci 패키지 구성과 코드 읽는 순서

기존 단일 예제를 **공통 처리와 메시지 본문 파서로 실제 분리**하고 이름을 Samsung 기준으로 정리했다.
Lua 모듈은 `samsung_*`, 프로토콜·필터 접두사는 `bthci_vendor.samsung`을 사용한다.
BluetoothKit `999c164`의 실제 BT Status / FW Build ID를 이관했고, 가상 학습 layout은 옵션으로 분리했다.
[이관 근거·필드·전체 URL](SAMSUNG_MIGRATION.md)에 계약과 검증 범위를 정리했다.

## 현재 실행되는 구조

```text
vendor_hci/                          # Wireshark에 복사하거나 연결하는 폴더
├── init.lua                         # samsung_dissector를 로드하는 진입점
├── samsung_dissector.lua             # Proto 등록, HCI 헤더, 본문 호출, 최종 오류 처리
├── samsung_fields.lua                # 공통·메시지별 ProtoField와 ProtoExpert 정의
├── samsung_reader.lua                # offset, 경계 검사, 값 읽기, 주소·subtree helper
├── samsung_commands.lua              # command opcode → 본문 파서
├── samsung_events.lua                # vendor subevent → 기능별 파서
├── samsung_events_bt_status.lua      # BT Status Tag → FW Build ID 본문
├── samsung_tutorial.lua              # 옵션으로 켜는 기존 학습 Command/Event
└── samsung_command_complete.lua      # 완료된 opcode → return parameters 파서
```

[init.lua](../vendor_hci/init.lua)는 다음처럼 모듈을 로드한다.

```lua
return require("samsung_dissector")
```

각 모듈에서는 `require("samsung_fields")`, `require("samsung_reader")`처럼 읽는다.
일반적인 `require("fields")`보다 다른 Lua plugin의 모듈과 이름이 겹칠 가능성을 줄인다.
모듈은 전역 변수를 만들기보다 함수·정의를 담은 테이블을 반환한다.
`samsung_dissector.lua`만 프로토콜과 vendor hook을 등록한다.

이 구성은 `require()`와 같은 이름의 모듈 캐시를 사용하는 프로젝트 설계다.
`init.lua`와 자동 스캔의 관계는 Wireshark 버전에 따라 다르며 다음 절처럼 구분해야 한다.
[공식 Lua 로딩 규칙](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html),
[공식 shared modules 예제](https://www.wireshark.org/docs/wsdg_html_chunked/wslua_require_example.html).

## 4.4의 자동 로드를 고려한 파일 배치

설치된 **4.4.8은 plugin 하위 폴더의 `init.lua`도 일반 Lua 파일로 취급하고,
하위 디렉터리를 먼저 스캔한다.** 현재 온라인 문서와 로컬 master에 있는
"`init.lua`가 있는 패키지의 하위 파일은 진입점에서만 로드한다"는 규칙을 그대로 적용할 수 없다.
4.4.8의 `lua_load_plugins()`와 `lua_load_plugin()`에서 확인할 수 있다.
[4.4.8 Lua 로더 소스](https://github.com/wireshark/wireshark/blob/wireshark-4.4.8/epan/wslua/init_wslua.c).

따라서 4.4.8도 지원하는 현재 구현은 모듈을 같은 폴더에 두고,
파일 이름 `samsung_fields.lua`와 모듈 이름 `samsung_fields`를 일치시킨다.
자동 스캔과 `require()`가 같은 캐시 항목을 사용하므로 이미 읽은 정의를 다시 생성하지 않는다.
`init.lua`만 실행하는 `-X` 방식과 폴더 복사·링크 방식 모두 검증했다.

앞서 제안했던 중첩 모듈 구성은 `-X`에서는 동작했지만 4.4.8의 폴더 자동 로드에서 실패했다.
실행 검증에 따라 파일 배치를 수정한 것이며, 필드·reader·본문 파서를 나누는 책임 구분은 같다.

## 먼저 읽을 파일

1. [samsung_events_bt_status.lua](../vendor_hci/samsung_events_bt_status.lua): 실제 Tag 분기와 짧은 FW Build ID 파서.
2. [samsung_fields.lua](../vendor_hci/samsung_fields.lua): `f.bt_status_tag`, `f.fw_build_id_length`, `f.fw_build_id`, `f.fw_build_id_bytes`의 필터·타입.
3. [samsung_events.lua](../vendor_hci/samsung_events.lua): Subevent `0x63`과 기능별 모듈 연결.
4. [samsung_dissector.lua](../vendor_hci/samsung_dissector.lua): HCI 헤더·공통 경계 검사·본문 호출.
5. [samsung_reader.lua](../vendor_hci/samsung_reader.lua): 길이 검사와 오류 분류.
6. [samsung_tutorial.lua](../vendor_hci/samsung_tutorial.lua): `decode_counted_bytes`부터 조건·배열·TLV로 확장.

실제 FW Build ID 본문은 다음이 전부다.

```lua
local function decode_fw_build_id(c)
    local length = c:u(f.fw_build_id_length, 1, "FW Build ID Length")
    local value = c:take(length, "FW Build ID")
    local item = c.tree:add_packet_field(f.fw_build_id, value, ENC_UTF_8)
    if length > 0 then item:add(f.fw_build_id_bytes, value) end
end
```

이때 `c`는 HCI 헤더, vendor subevent와 BT Status Tag를 지난 위치를 가리킨다.
이 파서는 Length와 그 길이만큼의 문자열을 읽는다. Tag는 같은 모듈의 상위 함수가 읽고,
메시지가 정확히 끝났는지는 공통 adapter가 확인한다.

기존 Sample Command/Event의 `f.sample` 공유 예제는 `samsung_tutorial.lua`에 있다.
학습 옵션은 기본으로 꺼져 있으며 실제 Command 파서가 정의되지 않은 `0xFC01`을 임의로 해석하지 않는다.

## 파일별로 맡는 일

| 파일 | 맡는 일 | 새 메시지를 추가할 때 |
|---|---|---|
| `init.lua` | 패키지 진입 | 보통 변경 없음 |
| `samsung_dissector.lua` | `Proto` 생성, 필드·expert 등록, vendor hook 등록, HCI 헤더 구분, 본문 선택, 최종 소비 길이와 오류 처리 | 새 HCI 진입 경로가 필요할 때 변경 |
| `samsung_fields.lua` | 필터 이름·타입·enum·단위 등 출력 정의 | 기존 필드를 재사용하고, 새 의미의 필드만 추가 |
| `samsung_reader.lua` | offset과 본문 경계, LE 숫자·bytes 읽기, 주소·RSSI·배열 subtree 표시, 입력 오류 식별 | 새 공통 기능이 필요할 때 변경 |
| `samsung_commands.lua` | opcode별 vendor Command 본문 | 해당 함수와 반환 테이블 항목 추가 |
| `samsung_events.lua` | vendor subevent 분기 | subevent와 기능별 파서 연결 |
| `samsung_events_bt_status.lua` | BT Status Tag 분기와 본문 | 해당 Tag 함수와 매핑 추가 |
| `samsung_tutorial.lua` | 가상 학습 layout, 기본 비활성 | 실제 디코더는 이 파일에 추가하지 않음 |
| `samsung_command_complete.lua` | opcode별 Command Complete 반환 본문 | 명세를 확보한 함수와 테이블 항목 추가 |

`samsung_fields.lua`는 `fields`와 `experts` 테이블을 반환한다.
`samsung_dissector.lua`에서 각각 `p.fields`, `p.experts`에 한 번 연결한다.
파서들은 같은 모듈의 `fields`를 참조하며, 별도의 `Proto`를 만들거나
자기 함수 안에서 `ProtoField`를 매번 생성하지 않는다.

[samsung_command_complete.lua](../vendor_hci/samsung_command_complete.lua)는 현재 빈 테이블을 반환한다.
이관 기준인 `999c164`에서도 알려진 반환 본문이 없으므로 빈 테이블이다.
`samsung_commands.lua`도 같은 이유로 빈 테이블을 반환한다.
해당 opcode의 파서가 없으면 `samsung_dissector.lua`가 raw bytes와 unknown 진단을 남긴다.
새 handler는 Num HCI Command Packets와 완료된 opcode가 소비된 다음,
return parameters의 첫 바이트부터 읽는다. Command Status의 표준 본문은 `samsung_dissector.lua`에서 다룬다.

## Event와 Command Complete를 나누는 이유

둘 다 HCI Event이지만 본문을 고르는 키와 헤더가 다르므로 파서 파일을 나누는 것을 추천한다.

| 항목 | `samsung_events.lua` | `samsung_command_complete.lua` |
|---|---|---|
| 바깥 HCI Event Code | vendor-specific `0xFF` | Command Complete `0x0E` |
| 파서 선택 키 | vendor subevent, 내부 message ID 등 | 완료된 Command opcode |
| 파서가 받는 시작 위치 | 공통 subevent가 소비된 다음. 추가 ID는 해당 파서가 소비 | Num HCI Command Packets와 opcode 다음의 return parameters |
| 흔한 본문 성격 | vendor가 정의한 알림·보고 | 특정 명령의 반환값 |

파일 분리가 별도의 Proto를 만드는 것은 아니다.
현재는 모두 하나의 `bthci_vendor.samsung` Proto와 `samsung_fields.lua`를 공유한다.
표준 Command Status `0x0F`는 Command Complete와 혼동하지 않고 공통 HCI 처리에서 소비한다.
반환 본문의 status 존재 여부와 layout은 opcode의 명세에 따라 파서가 확인한다.

## 패킷 하나를 코드로 따라가기

FW Build ID `FW-1`을 담은 합성 Samsung Event다.

```text
04 | ff 08 | 63 | 00 00 | 04 | 46 57 2d 31
H4   HCI    sub  tag LE   N    "FW-1"
```

1. native HCI Event dissector가 H4 타입 `04`를 제외한 HCI 바이트를 vendor hook으로 전달한다.
2. `samsung_dissector.lua`가 Event Code `0xFF`, Parameter Length `8`을 읽고 본문 끝을 정한다.
3. 공통 `subevent_code`로 `0x63`을 읽고 `samsung_events.lua`의 `events[0x63]`을 호출한다.
4. 연결된 `samsung_events_bt_status.lua`가 2바이트 Tag를 little-endian으로 읽는다.
5. `tags[0x0000]`이 `decode_fw_build_id(c)`를 선택한다. 이 함수는 Length `4`와 문자열 `FW-1`을 표시한다.
6. 공통 `c:finish()`가 여분 bytes가 없는지 확인한다. 입력 오류는 그때까지 읽은 필드와 함께 Expert Info에 남는다.

Tag가 `0x1234`라면 5번에서 unknown 진단과 남은 raw bytes를 표시한다.
알 수 없는 Tag의 본문에 Length 규칙을 적용하지 않는다.

가상 배열·TLV 예제는 `samsung_tutorial.lua`의 별도 테이블로 연결한다.
예를 들어 학습 frame 11은 `04 ff 07 e0 03 03 aa bb cc d6`이며,
학습 옵션을 켜면 `tutorial.events[0xE0] → kind 3 → decode_counted_bytes(c)` 순서로 호출된다.
길이 `3`, bytes `aabbcc`, RSSI `-42`가 나오며 기본 설정에서는 unknown이다.

## reader와 본문 파서의 경계

| API | 동작 |
|---|---|
| `reader.new(tvb, tree, first, limit)` | 시작 offset과 끝 경계를 가진 reader 생성 |
| `c:take(n, label)` | 경계를 확인하고 range 반환, offset 증가 |
| `c:u(field, n, label)` | LE 정수를 읽고 필드 추가, 숫자 반환 |
| `c:bytes(field, n, label)` | bytes 필드 추가, range 반환 |
| `c:finish()` | 정해진 경계까지 정확히 읽었는지 확인 |
| `c:fail(kind, text)` | malformed/truncated 등 예상한 입력 오류 발생 |
| `c:unknown(text)` | unknown 진단과 남은 raw bytes 표시 |
| `reader.bd_addr(c)` / `reader.rssi(c)` | 공통 주소·RSSI 필드 추가 |
| `reader.entry(c, i, name, decode)` | 배열 원소 subtree에서 파서 실행, 소비한 길이 반영 |

본문 파서는 실제 명세의 조건을 검사한다. 예를 들어 "남은 bytes가 2바이트 이상인가"는
reader의 일이고, "Scan Window가 Scan Interval보다 크면 안 된다"는 해당 파서의 일이다.
각 메시지 파서마다 동일한 `pcall`, 오류 표시, HCI 헤더 코드를 복사하지 않는다.

## 새 메시지를 추가하는 방법

1. `samsung_fields.lua`에서 기존 정의의 의미·타입·단위를 확인하고, 필요한 새 정의만 추가한다.
2. 해당 Command/Event/Command Complete 파일에 본문 함수와 ID 매핑을 추가한다.
3. 패키지 밖의 `tests/check_samsung.py`에 원본 계약의 패킷·기대값을 추가하고 TShark로 검증한다.
   가상 layout은 별도 `tests/make_examples.py`로 검사한다.

`samsung_events.lua`의 반환 테이블은 vendor subevent를 고르고, `samsung_events_bt_status.lua`의
`tags`는 BT Status Tag를 고른다. 다른 기능에도 내부 message ID나 version이 있다면
그 값을 읽는 계층에서 다음 파서를 선택한다. 어느 함수가 selector를 소비하는지 명확히 한다.

ID 매핑은 해당 파서 파일의 테이블에 둔다. 별도의 `routes.lua`와 파서 목록을 중복 관리하지 않는다.
반복 ID로 기존 항목을 실수로 덮어쓰지 않도록 검토한다.
통합 필터를 위해 같은 의미의 connection handle은 계속 `f.connection_handle`을 사용한다.
메시지별 파일 배치와 필터 이름의 구분은 독립적인 선택이다.

## 메시지가 많아질 때만 더 나누기

현재 BT Status는 기능별 모듈로 분리했다. 다른 기능도 함께 읽고 수정할 메시지가 모이면 모듈로 나눈다.
각 파일이 ID → 파서 테이블을 반환하고, 상위 모듈에서 명시적으로 합친다.
합칠 때는 같은 ID가 두 번 정의되면 오류로 처리한다.

```text
vendor_hci/
├── samsung_commands.lua                 # 기능별 테이블을 합치는 진입 모듈
├── samsung_commands_controller.lua
├── samsung_commands_diagnostics.lua
├── samsung_events.lua
├── samsung_events_connection.lua
├── samsung_events_diagnostics.lua
├── samsung_command_complete.lua
└── samsung_structs.lua                  # 여러 파서가 공유하는 구조체가 생기면 추가
```

위 기능별 모듈과 `samsung_structs.lua`는 향후 확장 예다. 짧은 메시지 하나마다 파일을 만드는 대신,
함께 읽고 수정하는 메시지를 묶는다. 실제로 여러 파서가 공유하는 구조체가 생기면 그 원소 파서를 분리한다.
`samsung_fields.lua`도 커지면 `samsung_fields_common.lua`, `samsung_fields_diagnostics.lua` 등으로 나누되,
하나의 상위 모듈이 전체 필드를 모으고 공통 필드를 한 번만 정의한다.
하위 디렉터리로 바꾸려면 지원할 Wireshark 버전의 자동 로드까지 다시 확인한다.

연결 추적이나 재조립이 필요해질 때는 상태 모듈을 추가한다.
처음부터 상태 관리자, 플러그인 자동 발견, 별도 스키마 언어와 코드 생성기를 만들 필요는 없다.
본문 파서는 일반 Lua 함수와 명시적인 테이블로 시작하면 된다.

## Samsung 이름으로 정리한 항목

| 이전 예제 | 현재 |
|---|---|
| `bkv_tutorial.lua` | `init.lua`와 `samsung_*.lua` 모듈 |
| 프로토콜 `bkv` | `bthci_vendor.samsung` |
| `bkv.handle` | `bthci_vendor.samsung.connection_handle` |
| `bkv.address` | `bthci_vendor.samsung.bd_addr` |
| `bkv.route` | `bthci_vendor.samsung.subevent_code` |
| 그 외 `bkv.*` | 같은 접미사의 `bthci_vendor.samsung.*` |
| `-d bthci_cmd.vendor=bkv` | `-d bthci_cmd.vendor=bthci_vendor.samsung` |

모듈 이름, Proto·필터 이름, 테스트의 기대 필드와 문서의 실행 명령을 함께 정리했다.
이전 필터 이름은 alias로 중복 등록하지 않는다. 저장한 필터나 `-e` 인수도 위 표대로 갱신한다.
현재 실제로 이관한 메시지와 학습 옵션의 차이는 [Samsung 이관 문서](SAMSUNG_MIGRATION.md)에 있다.
[Samsung 명명 규칙](WIRESHARK_LUA_DISSECTOR_GUIDE.md#59-samsung-프로토콜과-필드-이름)을 참고한다.

## 설치와 검증

배포 단위는 `vendor_hci` 폴더 전체이고 진입점은 계속 `vendor_hci/init.lua`다.
Windows의 복사·junction, macOS/Linux의 복사·심볼릭 링크, `-X lua_script` 개발 흐름은 같다.
`samsung_*.lua`를 모두 함께 배포하고, 이전 단일 예제 직접 실행 대신 `init.lua`를 지정한다.
기존 복사본을 갱신할 때는 폐기된 Lua 파일이 남지 않도록 설치 폴더 전체를 교체한다.
새로운 빌드 과정은 필요하지 않다.

현재 `check_samsung.py`는 23개 Samsung case와 367개 잘림 위치, 필터·byte range·학습 옵션 격리·재분석·자동 로드를 검사한다.
`make_examples.py`는 학습 옵션을 켜고 기존 28개 case와 208개 잘림 위치를 검사한다.

참고로 최초 모듈 분리·이름 변경 시 Wireshark/TShark 4.4.8에서 다음도 확인했다.

- 기존 28개 예제의 필드·진단 기대값과 일반 분석/두 번 분석 결과 일치.
- 208개 잘림 위치에서 Lua Error가 발생하지 않는 것.
- 236개 정상·오류·잘림 입력에서 생성된 186개 vendor 트리가 의도한 이름 변경을 제외하고 분리 전과 동일한 것.
  HCI 헤더 단계에서 잘린 일부 frame은 vendor hook까지 도달하지 않아 Samsung 트리가 없다.
- 등록된 필드 목록에서도 위 이름 변경 외의 타입·표시·mask 변경이 없는 것.
- 다른 작업 디렉터리에서 `-X`, 폴더 복사, 심볼릭 링크로 로드해 같은 결과가 나오는 것.

관련 문서: [필드 관리 규칙](WIRESHARK_LUA_DISSECTOR_GUIDE.md#이-프로젝트의-필드-관리-규칙),
[Windows 실행 가이드](WINDOWS_SETUP.md),
[참고자료와 전체 URL](WIRESHARK_LUA_DISSECTOR_GUIDE.md#10-참고자료와-전체-url).
