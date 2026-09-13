# 합성 패킷 fixtures

현재 패킷과 기대값은 [make_examples.py](../make_examples.py)의 `CASES`에 정의되어 있다.
다음 명령으로 btsnoop 파일을 생성한다.

```sh
python3 tests/make_examples.py /tmp/vendor-hci-examples.btsnoop
```

`--check tshark`를 추가하면 생성한 패킷을 실제 Lua 패키지로 분석해 검증한다.
캡처 잘림 테스트에서는 원래 길이와 저장된 길이를 다르게 기록한다.
같은 패키지를 임시 plugin 폴더에 복사하여, `-X`를 사용한 실행과 자동 로드의 출력도 비교한다.
프로토콜은 `bthci_vendor.samsung`, 공통 handle과 주소는 각각 `.connection_handle`, `.bd_addr`다.

새 메시지를 이관할 때 wire 명세에서 만든 합성 패킷과 기대 필드를 추가한다.
count=0, 경계 길이, unknown selector, 잘린 원소, 여분 bytes를 해당 메시지 규칙에 맞춰 포함한다.
생성된 캡처는 다시 만들 수 있으므로 Git 추적 대상에서 제외한다.
