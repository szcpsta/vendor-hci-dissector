# vendor_hci 패키지의 권장 구성

`bkv_tutorial.lua`는 여러 파싱 기법을 한 파일에서 찾아볼 수 있게 만든 학습 예제다.
필드 정의, Expert Info, 범위 검사, 주소 변환, HCI 헤더 처리, 메시지 분기와 8종의 학습용 본문이
함께 들어 있어 실제 메시지 하나를 추가할 때 필요한 코드보다 복잡하게 보인다.

실제 vendor 구현에서는 **공통 처리와 메시지 본문 파서를 분리**한다.
새 디코더 작성자가 주로 보는 파일은 Command/Event 본문 파서와 공통 필드 목록이 되도록 구성한다.
아래는 Samsung을 가정한 설계안이다. 현재 실행 가능한 `vendor_hci/init.lua`와
`bkv_tutorial.lua`를 이미 이 구조로 바꿨다는 뜻은 아니다.

## 처음 사용할 구조

```text
vendor_hci/                       # Wireshark에 복사하거나 연결하는 폴더
├── init.lua                      # samsung.dissector를 로드하는 진입점
└── samsung/                      # Lua 모듈 이름을 구분하는 디렉터리
    ├── dissector.lua             # Proto 등록, HCI 헤더, 본문 호출, 최종 오류 처리
    ├── fields.lua                # 공통·메시지별 ProtoField와 ProtoExpert 정의
    ├── reader.lua                # offset, 경계 검사, 값 읽기, 주소 변환
    ├── commands.lua              # command opcode → 본문 파서
    ├── events.lua                # vendor subevent/message ID → 본문 파서
    └── command_complete.lua      # 완료된 opcode → return parameters 파서
```

처음부터 메시지마다 파일을 만들 필요는 없다. 각 메시지 파서는 작은 함수로 작성하고,
한 파일에 관련 함수와 ID별 함수 테이블을 함께 둔다.
아직 해석할 Command Complete 반환 형식이 없다면 그 테이블은 비어 있어도 된다.
현재 예제처럼 반환 형식을 모르면 raw bytes와 unknown 진단을 남긴다.

`init.lua`는 다음처럼 짧게 유지할 수 있다.

```lua
return require("samsung.dissector")
```

각 모듈에서는 `require("samsung.fields")`, `require("samsung.reader")`처럼 읽는다.
일반적인 `require("fields")`보다 다른 Lua plugin의 모듈과 이름이 겹칠 가능성을 줄인다.
여기서 `samsung`은 Lua 모듈 이름이고, 필터 접두사인 `bthci_vendor.samsung`과는 별개다.
외부 폴더 `vendor_hci`를 바꾸더라도 내부 모듈 이름을 반드시 바꿀 필요는 없다.

Wireshark는 `init.lua`가 있는 plugin 하위 폴더를 패키지로 로드하고, 추가 모듈은
그 진입점에서 읽도록 지원한다. 모듈은 전역 변수를 만들기보다 함수·정의를 담은 테이블을 반환한다.
이 구성은 공식 모듈 로딩 방식을 이용한 프로젝트 설계안이며, Wireshark가 강제하는 파일 배치는 아니다.
[공식 Lua 로딩 규칙](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html),
[공식 shared modules 예제](https://www.wireshark.org/docs/wsdg_html_chunked/wslua_require_example.html).

## 파일별로 맡을 일

| 파일 | 맡을 일 | 새 메시지를 추가할 때 |
|---|---|---|
| `init.lua` | 패키지 진입 | 보통 변경 없음 |
| `dissector.lua` | `Proto` 생성, 필드·expert 등록, vendor hook 등록, HCI 헤더 구분, 본문 선택, 최종 소비 길이와 오류 처리 | 새 HCI 진입 경로가 필요할 때 변경 |
| `fields.lua` | 필터 이름·타입·enum·단위 등 출력 정의 | 기존 필드를 재사용하고, 새 의미의 필드만 추가 |
| `reader.lua` | 현재 offset과 본문 경계 관리, LE 숫자·bytes 읽기, 주소 변환, 입력 오류와 프로그래밍 오류 구분 | 새 공통 읽기 기능이 필요할 때 변경 |
| `commands.lua` | opcode별 vendor Command 본문 | 해당 함수와 테이블 항목 추가 |
| `events.lua` | vendor Event 본문과 내부 selector 분기 | 해당 함수와 테이블 항목 추가 |
| `command_complete.lua` | opcode별 Command Complete 반환 본문 | 해당 함수와 테이블 항목 추가 |

`fields.lua`는 `fields`와 `experts` 테이블을 반환하도록 정할 수 있다.
`dissector.lua`에서 각각 `p.fields`, `p.experts`에 한 번 연결한다.
파서들은 같은 모듈의 `fields`를 참조한다. 파서가 별도의 `Proto`를 만들거나
자기 함수 안에서 `ProtoField`를 매번 생성하지 않는다.

Command와 Event의 **코드는 나누되 공통 필드는 공유**한다.
양쪽에서 같은 HCI connection handle을 표시한다면
`bthci_vendor.samsung.connection_handle`을 가리키는 동일한 필드 정의를 사용한다.
메시지별 파일 배치와 필터 이름의 구분은 독립적인 선택이다.

## 공통 처리와 본문 파서의 경계

분석 흐름은 다음과 같이 유지한다.

```text
native HCI dissector
    ↓ vendor hook
samsung/dissector.lua
    ├── HCI 종류·헤더·선언된 길이 확인
    ├── 본문 시작 offset과 끝 경계를 가진 reader 생성
    ├── Command / vendor Event / Command Complete 본문 파서 호출
    └── 남은 bytes 및 입력 오류 처리
```

본문 파서가 받는 reader는 **그 파서가 읽어야 할 본문의 시작**을 가리킨다.
예를 들어 Command 파서는 opcode와 Parameter Length가 소비된 다음부터 읽는다.
Command Complete 파서는 Num HCI Command Packets와 완료된 opcode 다음의 return parameters부터 읽는다.
Event에서는 subevent/message ID를 어느 함수가 소비하는지 정하고, 다음 함수가 중복 소비하지 않게 한다.
Command Status의 표준 본문은 공통 HCI 처리에서 다룬다.

reader는 offset과 경계를 검사하고, 본문 파서는 실제 명세의 조건을 검사한다.
예를 들어 "남은 bytes가 2바이트 이상인가"는 reader의 일이고,
"Scan Window가 Scan Interval보다 크면 안 된다"는 해당 파서의 일이다.
잘못된 입력을 표시하는 `ProtoExpert`와 예외 분류 방식은 공통 처리에 모은다.
각 메시지 파서마다 동일한 `pcall`, 오류 표시, HCI 헤더 코드를 복사하지 않는다.

## 새 Event 파서가 실제로 보일 형태

다음은 **설명용 가상 layout**이다. `0x01`은 실제 Samsung subevent를 뜻하지 않는다.
본문은 `connection_handle:uint16 LE → data_length:uint8 → data:bytes[data_length]`라고 가정한다.
아래 `c:u`, `c:bytes`는 현재 학습 예제의 reader API와 같은 형태다.

```lua
-- samsung/events.lua
local f = require("samsung.fields").fields

local function decode_link_report(c)
    c:u(f.connection_handle, 2, "Connection Handle")
    local n = c:u(f.link_report_data_length, 1, "Data Length")
    c:bytes(f.link_report_data, n, "Data")
end

return {
    [0x01] = decode_link_report -- 설명용 subevent ID
}
```

이 예의 필드 정의는 `fields.lua`에서 관리한다.

| 코드에서 참조하는 키 | 필터 이름 | 타입 |
|---|---|---|
| `connection_handle` | `bthci_vendor.samsung.connection_handle` | `uint16` |
| `link_report_data_length` | `bthci_vendor.samsung.link_report.data_length` | `uint8` |
| `link_report_data` | `bthci_vendor.samsung.link_report.data` | `bytes` |

기존 `connection_handle`을 재사용하고, 이 메시지에 필요한 새 필드만 정의한다.
입력 잘림 검사와 offset 증가는 reader가 담당한다.
이 예는 권장 모듈의 모양을 설명하는 코드이며, 현재 학습 패키지에서 `samsung.*`를 로드할 수 있는 것은 아니다.

새 메시지 추가 작업은 보통 다음 세 가지다.

1. 기존 공통 필드를 확인하고, 필요한 새 정의만 `fields.lua`에 추가한다.
2. 해당 Command/Event/Command Complete 파일에 본문 함수와 ID 매핑을 추가한다.
3. 패키지 밖의 `tests/`에 패킷·기대값을 추가하고 실제 TShark로 필터와 값·오류 동작을 확인한다.

처음에는 ID 매핑도 해당 파서 파일의 반환 테이블에 둔다. 별도의 `routes.lua`와 파서 목록을
중복 관리할 필요는 없다. 반복 ID를 실수로 덮어쓰지 않도록 테이블을 검토하고,
이후 여러 모듈의 테이블을 합칠 때는 같은 ID가 두 번 정의되면 오류로 처리한다.

## 메시지가 많아질 때만 더 나누기

`events.lua`가 다시 읽기 어려울 정도로 커지면 기능별 모듈로 나눈다.
파일마다 같은 HCI 종류의 ID → 파서 테이블을 반환하고, 상위 모듈에서 명시적으로 합친다.

```text
samsung/
├── commands.lua                  # commands/*의 테이블을 합치는 진입 모듈
├── commands/
│   ├── controller.lua
│   └── diagnostics.lua
├── events.lua                    # events/*의 테이블을 합치는 진입 모듈
├── events/
│   ├── connection.lua
│   └── diagnostics.lua
├── command_complete.lua
└── structs.lua                   # 실제로 여러 파서가 공유하는 구조체가 생기면 추가
```

기능 이름은 실제 vendor 명세를 보고 정한다. 짧은 메시지 하나마다 파일을 만드는 대신,
함께 읽고 수정하는 메시지를 묶는다. 반복 구조체의 파서는 `structs.lua`로 분리할 수 있다.
예를 들어 여러 Event가 같은 `CsStepEntry` 배열 원소를 사용한다면 그 원소 파서가 분리 대상이다.

`fields.lua`도 커지면 `fields/common.lua`, `fields/diagnostics.lua` 등으로 나누되,
하나의 상위 `fields.lua`가 전체 필드를 모아 등록할 수 있도록 한다.
connection handle·공통 주소 등은 common에 한 번만 정의한다.
동일한 필터 이름을 각 기능 모듈에서 따로 만들어 놓는 방식은 사용하지 않는다.

연결 추적이나 재조립이 실제로 필요해질 때는 별도의 상태 모듈을 추가한다.
처음부터 상태 관리자, 플러그인 자동 발견, 별도 스키마 언어와 코드 생성기를 만들 필요는 없다.
본문 파서는 일반 Lua 함수와 명시적인 테이블로 시작하면 된다.

## 설치와 검증

이 구성이 되어도 배포 단위는 `vendor_hci` 폴더 전체이고 진입점은 `vendor_hci/init.lua`다.
Windows의 복사·junction, macOS/Linux의 복사·심볼릭 링크, `-X lua_script` 개발 흐름은 같다.
파일을 분리하는 것만으로 새로운 빌드 과정이 생기지는 않는다.

학습 예제를 실제로 분리할 때는 먼저 필터 이름·wire 처리·진단 결과를 유지하며 파일만 옮긴다.
기존 28개 예제, 208개 잘림 위치, 일반 분석과 두 번 분석의 일치 검사를 다시 실행한다.
Samsung의 실제 명세 이관은 별도 변경으로 진행하고, 해당 명세의 패킷으로 검증한다.

관련 문서: [필드 관리 규칙](WIRESHARK_LUA_DISSECTOR_GUIDE.md#이-프로젝트의-필드-관리-규칙),
[Windows 실행 가이드](WINDOWS_SETUP.md),
[참고자료와 전체 URL](WIRESHARK_LUA_DISSECTOR_GUIDE.md#10-참고자료와-전체-url).
