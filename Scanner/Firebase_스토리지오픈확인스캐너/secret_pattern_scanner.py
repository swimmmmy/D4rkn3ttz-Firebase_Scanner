#!/usr/bin/env python3
"""
Firebase/Cloud Secret Pattern Scanner (v2)
--------------------------------------------
팀원(연우 언니)의 Supabase 스캔 방식을 참고해서 만든 버전.

기존 v1과의 차이:
  v1: 한 사이트의 Firebase RTDB/Firestore/Storage가 "열려있는지"를 직접 요청해서 확인
      → 실시간으로 대상 서버에 접근 시도 (더 조심스러워야 함)
  v2: 공개적으로 서빙되는 JS 파일 안에 시크릿(키)이 그대로 하드코딩돼 있는지
      "읽기만"으로 정규식 패턴 매칭 → 브라우저가 어차피 받는 공개 파일을 읽는 것뿐이라
      더 안전하고, 팀원 워크플로와 산출물 형식(CSV)도 맞출 수 있음

여전히 지키는 원칙:
  - JS 파일을 GET으로 읽기만 함 (실행/eval 안 함)
  - 매치된 값은 마스킹해서 저장 (앞 4자만 노출, 나머지 ***)
  - 실제 DB/API 접근 시도는 하지 않음 — "패턴이 있다"까지만 확인
  - 결과는 REVIEW_REQUIRED 상태로 저장 — 팀 검증 체크리스트로 넘길 것
"""

import argparse
import csv
import hashlib
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import requests

RATE_LIMIT_DELAY = 1.0
REQUEST_TIMEOUT = 10
USER_AGENT = "SecretPatternChecker/1.0 (+security-research; read-only)"
CONTEXT_WINDOW = 250  # 매치된 위치 앞뒤로 몇 글자까지 컨텍스트로 저장할지

# (패턴 이름, 정규식, base_confidence, 설명)
PATTERNS = [
    ("FIREBASE_API_KEY", re.compile(r'apiKey["\']?\s*[:=]\s*["\'](AIza[A-Za-z0-9_\-]{35})["\']'),
     "MEDIUM", "Firebase apiKey (공개돼도 되는 값이지만 다른 설정 오류와 함께면 위험도↑)"),
    ("FIREBASE_DATABASE_URL", re.compile(r'databaseURL["\']?\s*[:=]\s*["\'](https://[a-z0-9\-]+\.(?:firebaseio\.com|[a-z0-9\-]+\.firebasedatabase\.app))["\']'),
     "LOW", "Firebase Realtime Database URL"),
    ("SUPABASE_URL_KEY_PAIR", re.compile(r'(https://[a-z0-9]{15,25}\.supabase\.co)["\'][^;]{0,60}["\'](eyJ[A-Za-z0-9_\-\.]{20,}|sb_[a-z]+_[A-Za-z0-9_\-]{20,})["\']'),
     "HIGH", "Supabase 프로젝트 URL + anon/service key 쌍"),
    ("SUPABASE_SECRET_KEY", re.compile(r'\bsb_(?:secret|service)_[A-Za-z0-9_\-]{20,}\b'),
     "HIGH", "Supabase secret/service key 후보"),
    ("JWT_TOKEN", re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'),
     "MEDIUM", "JWT 형식 문자열 (anon key일 수도, 세션 토큰일 수도 있음 — 맥락 확인 필요)"),
    ("PRIVATE_KEY_HEADER", re.compile(r'-----BEGIN (?:RSA |EC |)PRIVATE KEY-----'),
     "CRITICAL", "Private Key PEM 헤더 — 코드에 직접 박혀 있으면 심각"),
    ("LABELED_SECRET_ASSIGNMENT", re.compile(r'\b([A-Z][A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE_KEY|API_KEY|TOKEN)[A-Z0-9_]*)\s*[:=]\s*["\']([^"\']{8,})["\']'),
     "HIGH", "민감해 보이는 환경변수 이름에 값이 그대로 할당된 경우"),
    ("AWS_ACCESS_KEY", re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
     "CRITICAL", "AWS Access Key ID 패턴"),
]


@dataclass
class Finding:
    detected_utc: str
    url: str
    source: str
    pattern_name: str
    base_confidence: str
    masked_value: str
    context: str
    description: str
    evidence_hash: str


def mask_value(value: str) -> str:
    if len(value) <= 8:
        return value[:2] + "*" * max(0, len(value) - 2)
    return value[:4] + "*" * 16 + value[-4:]


def make_context(text: str, start: int, end: int) -> str:
    lo = max(0, start - CONTEXT_WINDOW)
    hi = min(len(text), end + CONTEXT_WINDOW)
    snippet = text[lo:hi].replace("\n", " ")
    return snippet


def fetch(url: str) -> str | None:
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        if resp.status_code == 200:
            return resp.text
        print(f"  [!] HTTP {resp.status_code}: {url}", file=sys.stderr)
    except requests.RequestException as exc:
        print(f"  [!] 요청 실패: {url} ({exc})", file=sys.stderr)
    finally:
        time.sleep(RATE_LIMIT_DELAY)
    return None


def find_js_asset_urls(page_url: str, html: str) -> list:
    """페이지 HTML에서 <script src="..."> 형태의 JS 파일 링크를 뽑아냄."""
    from urllib.parse import urljoin
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html, re.IGNORECASE)
    return [urljoin(page_url, s) for s in srcs]


def scan_text(text: str, source_url: str) -> list:
    findings = []
    for name, pattern, confidence, desc in PATTERNS:
        for m in pattern.finditer(text):
            value = m.group(0)
            masked = mask_value(value)
            context = make_context(text, m.start(), m.end())
            ev_hash = "sha256:" + hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()
            findings.append(Finding(
                detected_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                url=source_url,
                source=source_url,
                pattern_name=name,
                base_confidence=confidence,
                masked_value=masked,
                context=context,
                description=desc,
                evidence_hash=ev_hash,
            ))
    return findings


def scan_target(target: str) -> list:
    print(f"\n[*] 대상 확인 중: {target}")
    all_findings = []

    html = fetch(target)
    if html is None:
        return all_findings

    # 페이지 자체(인라인 스크립트 포함)도 스캔
    all_findings.extend(scan_text(html, target))

    # 링크된 JS 파일들도 하나씩 스캔
    js_urls = find_js_asset_urls(target, html)
    print(f"    JS 파일 {len(js_urls)}개 발견")
    for js_url in js_urls:
        js_text = fetch(js_url)
        if js_text:
            found = scan_text(js_text, js_url)
            all_findings.extend(found)

    if all_findings:
        print(f"    [!] {len(all_findings)}건 패턴 매치 — REVIEW_REQUIRED")
        for f in all_findings:
            print(f"        - {f.pattern_name} ({f.base_confidence}): {f.masked_value}")
    else:
        print("    매치 없음")

    return all_findings


def save_csv(findings: list, out_path: str):
    fields = [
        "detected_utc", "url", "source", "pattern_name", "base_confidence",
        "status", "masked_value", "context", "description", "evidence_hash",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for finding in findings:
            writer.writerow({
                "detected_utc": finding.detected_utc,
                "url": finding.url,
                "source": finding.source,
                "pattern_name": finding.pattern_name,
                "base_confidence": finding.base_confidence,
                "status": "REVIEW_REQUIRED",
                "masked_value": finding.masked_value,
                "context": finding.context,
                "description": finding.description,
                "evidence_hash": finding.evidence_hash,
            })


def load_targets(path: str) -> list:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def main():
    parser = argparse.ArgumentParser(description="공개 JS 번들 시크릿 패턴 스캐너 (읽기 전용)")
    parser.add_argument("targets_file", help="한 줄에 하나씩: 스캔할 웹사이트 URL")
    parser.add_argument("-o", "--output", default="secret_scan_results.csv", help="결과 CSV 저장 경로")
    args = parser.parse_args()

    targets = load_targets(args.targets_file)
    print(f"총 {len(targets)}개 대상 스캔 시작 (읽기 전용, 요청 간 {RATE_LIMIT_DELAY}초 대기)")

    all_findings = []
    for t in targets:
        all_findings.extend(scan_target(t))

    save_csv(all_findings, args.output)
    print(f"\n결과 저장 완료: {args.output} (총 {len(all_findings)}건)")

    critical = [f for f in all_findings if f.base_confidence == "CRITICAL"]
    if critical:
        print(f"\n⚠️  CRITICAL {len(critical)}건 — 팀 검증 체크리스트로 넘겨서 실제 민감정보인지 2차 확인하세요.")


if __name__ == "__main__":
    main()
