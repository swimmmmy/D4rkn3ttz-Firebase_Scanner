# FirebaseSecurityAuditor 1.0.0

승인된 웹사이트와 Firebase 프로젝트를 대상으로 하는 read-only 보안 점검 도구입니다. HTML/JavaScript 정적 discovery, RTDB·Firestore·Storage의 제한된 읽기 검사, 민감정보 마스킹, Security Rules 분석, 보고서와 baseline diff를 제공합니다.

## 안전 보장

- 외부 요청에는 유효한 Scope와 `--ack-authorized`가 모두 필요합니다.
- 운영 환경의 PUT/PATCH/DELETE와 일반 POST는 중앙 요청 게이트에서 차단합니다.
- POST 예외는 schema와 limit을 검증한 Firestore `documents:runQuery`뿐입니다.
- 원격 JavaScript를 실행하지 않으며 raw response와 원본 secret을 저장하지 않습니다.
- 선택적 `--auth-fixtures`는 token 원문이 아닌 환경변수 참조만 허용하며 A↔B owner-only read 격리를 검사합니다.
- Firebase Web API Key와 공개 `firebaseConfig` 자체는 INFO discovery이며 취약점이 아닙니다.
- 외부 telemetry, 자동 update check, 보고서 업로드가 없습니다.

빠른 사용법은 `실행방법.md`, 보안 모델은 `SECURITY.md`, 검증 증거는 `test-results/final-verification.md`를 확인하세요.

## Source 실행

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\설치.ps1
.\실행.ps1 version
.\실행.ps1 discover --file .\samples\offline-discovery\app.js --offline --output .\reports
```

Emulator 검증 의존성까지 설치하려면 Java 21과 Node.js 20+ 준비 후 `.\설치.ps1 -IncludeEmulator`를 사용합니다.

종료 코드는 0 정상, 1 HIGH/CRITICAL, 2 Scope/승인/입력, 3 네트워크/실행, 4 보고서, 5 자체점검/무결성 오류입니다.
