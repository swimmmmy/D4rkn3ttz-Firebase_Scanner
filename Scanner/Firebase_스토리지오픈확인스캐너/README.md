# Firebase 설정 오류 읽기 전용 스캐너

## 뭘 하는 도구인가

웹사이트 하나(또는 여러 개)를 넣으면:
1. 페이지 코드에서 공개된 Firebase 설정값(apiKey, projectId 등 — 원래 공개돼도 되는 값)을 찾고
2. 그 프로젝트의 **Realtime Database / Firestore / Storage**가
   **인증 없이 읽기(GET)만으로 열람 가능한 상태인지**를 확인합니다.

**절대 하지 않는 것:**
- 쓰기(PUT/PATCH/DELETE) 요청 — 코드에 아예 없음
- 실제 데이터 내용 저장/출력 — "열려있다"는 사실과 응답 길이만 기록
- 대량 무작위 스캔 — targets.txt에 넣은 것만 확인

## 설치

```bash
pip install requests --break-system-packages
```

## 사용법

```bash
# 1. 대상 목록 만들기 (targets.example.txt 복사해서 채우기)
cp targets.example.txt targets.txt
# targets.txt에 확인하고 싶은 URL 또는 project-id를 한 줄씩 입력

# 2. 스캔 실행
python3 firebase_scanner.py targets.txt -o scan_results.csv
```

## 결과 읽는 법

CSV의 `overall_risk` 컬럼:
- `OK - 노출 없음` → 정상
- `CRITICAL - 열려있음, 즉시 스캔 중단 후 팀 보고` → **여기서 스캐너 작업을 멈추고**,
  팀의 데이터 분석/검증 체크리스트로 넘겨서 심각도 판정 → 2차 검증 → 책임있는 공개 절차를 따르세요.
  이 스캐너는 "열려있는지 여부"만 알려줄 뿐, 실제 데이터를 받아오지 않습니다.
- `UNKNOWN - 재확인 필요` → 네트워크 오류 등으로 판단이 애매한 경우, 시간을 두고 재실행

## 다음 단계로 참고할 오픈소스

이미 후보로 찾아두신 도구들과 함께 쓰면 좋습니다:
- OpenFirebase (github.com/Icex0/OpenFirebase) — 모바일 앱(APK/IPA)에서 Firebase 설정 자동 추출
- cloud_enum (github.com/initstring/cloud_enum) — Firebase 외 다른 클라우드(S3, Azure 등)까지 넓혀서 확인

## 검증 흐름 (팀 파이프라인과 연결)

```
이 스캐너로 1차 스캔
   → "열려있음" 뜨면 즉시 중단
   → 팀 체크리스트로 심각도 판정 (개인정보/credential 여부)
   → 심각도 '상'만 2차 정밀 검증
   → 확정 리스트를 보고서 팀에 전달
```
