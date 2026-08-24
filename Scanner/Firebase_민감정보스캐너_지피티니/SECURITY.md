# Security Policy

이 도구는 소유하거나 명시적으로 승인을 받은 대상 전용입니다. Scope 밖 endpoint, credential 추측, API 열거, brute force, App Check 우회, 운영 write는 금지됩니다.

Token은 환경변수 또는 OS keyring으로만 전달하고 CLI·YAML·로그에 원문을 두지 않습니다. report에는 masked preview와 digest만 기록하며 raw response 저장 기능은 v1.0에 없습니다. 결과 보존 기간 후 `purge`로 보고서와 로그를 삭제하되 release·source·Acceptance는 삭제하지 않습니다.

취약점 신고에는 제품 version, 재현 가능한 로컬 fixture, 마스킹된 로그를 포함하고 실제 사용자 데이터나 credential을 첨부하지 마세요. 자동 telemetry와 crash upload는 없습니다.

