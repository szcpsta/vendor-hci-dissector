# Vendor HCI Dissector

Bluetooth HCI vendor decoder를 Wireshark Lua dissector로 이관하기 위한 레포지토리다.
현재는 BluetoothKit SG를 참고한 **실행 가능한 학습 예제와 마이그레이션 가이드**를 포함한다.
실제 vendor decoder 이관은 해당 구현과 wire 명세를 확보한 뒤 진행한다.

- [상세 작성·마이그레이션 가이드](docs/WIRESHARK_LUA_DISSECTOR_GUIDE.md)
- [참고자료와 전체 URL](docs/WIRESHARK_LUA_DISSECTOR_GUIDE.md#10-참고자료와-전체-url)
- [검증용 패킷과 기대값](tests/make_examples.py)

## 구조

```text
vendor-hci-dissector/
├── vendor_hci/                     # Wireshark에 설치할 패키지
│   ├── init.lua                    # 패키지 진입점
│   └── bkv_tutorial.lua            # 검증된 예제 dissector
├── docs/
│   └── WIRESHARK_LUA_DISSECTOR_GUIDE.md
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

현재 구현은 작은 단일 모듈로 유지한다. 실제 vendor 메시지가 늘면 `fields.lua`, `reader.lua`,
`commands.lua`, `events.lua`, `structs.lua`로 책임에 따라 분리할 수 있다.
필드·프로토콜 등록은 패킷 콜백 밖에서 한 번 수행하고, 순서가 필요한 모듈은 명시적으로 로드한다.

## 요구 환경

- 검증 환경: **Wireshark/TShark 4.4.8, 내장 Lua 5.4.6**.
- 예제 패킷 생성과 검증: **Python 3**, 표준 라이브러리만 사용.
- 다른 Wireshark/Lua 버전은 아래 검증 명령으로 확인한다.

Wireshark가 내장 Lua와 API를 제공하며, `vendor_hci/init.lua`를 로드하면 프로토콜이 등록된다.
현재 프로토콜 필터 이름은 `bkv`, 표시 이름은 `BluetoothKit Vendor Tutorial`이다.

## 빠른 실행

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
