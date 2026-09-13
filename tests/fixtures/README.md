# 검증용 패킷

실제 장비 캡처를 포함하지 않는다. Python 표준 라이브러리로 재생성하는 H4 btsnoop이다.

- `python3 tests/check_samsung.py <output.btsnoop> --check <tshark>`:
  BluetoothKit `999c164`의 FW Build ID와 네 원본 테스트 패킷을 검증한다.
  UTF-8, 빈 문자열, 최대 길이, unknown tag, 길이 오류·여분 bytes·캡처 잘림을 포함한다.
  기본 설정에서 가상 학습 layout이 동작하지 않는지도 확인한다.
- `python3 tests/make_examples.py <output.btsnoop> --check <tshark>`:
  SampleVendorContract와 가상 조건·배열·TLV 예제다. 검증 시 학습 옵션을 자동으로 켠다.
  이 캡처를 직접 열 때는 `-o bthci_vendor.samsung.enable_tutorial:TRUE`가 필요하다.

`--check` 없이 실행하면 캡처만 생성한다. 두 스크립트 모두 일반/두 번 분석과 바이트 경계 잘림,
임시 폴더 복사 자동 로드를 검사한다. 생성된 캡처와 Python 캐시는 Git 추적 대상에서 제외한다.

실제 메시지를 추가할 때는 `check_samsung.py`에 원본 계약과 기대값을 추가한다.
[Samsung 이관 문서](../../docs/SAMSUNG_MIGRATION.md)에 원본 revision과 전체 URL이 있다.

`samsung_999c164.json`은 원본 Core·Samsung·SG를 .NET SDK 9.0.202로 컴파일해 얻은
22개 완전한 H4 입력의 결과다. 입력 hex, 반환 타입, `BuildFields()` 값을 고정해 두었고
`check_samsung.py`가 이를 TShark 출력과 비교한다. C# invalid와 Lua 부분 필드 유지,
FT_STRING의 NUL 표시 제한은 이관 문서에 설명했다. 기준값을 갱신할 때는 원본 revision에서
`HciPacketParser.TryParse` → `HciDecoder(new SamsungVendorDecoder()).Decode` → `BuildFields()`를
다시 실행한다. 일반 검증에는 .NET을 설치할 필요가 없다.
