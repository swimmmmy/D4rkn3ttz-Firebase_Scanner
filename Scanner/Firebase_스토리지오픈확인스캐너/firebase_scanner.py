#!/usr/bin/env python3
"""
Firebase Misconfiguration Read-Only Scanner
--------------------------------------------
목적: 팀 프로젝트(유출된 개인정보는 어디로 가는가?) - 파일공유/바이브코딩 유출
      서브팀용 Firebase 설정 오류 점검 도구

핵심 원칙 (반드시 지킬 것):
  1. 읽기(GET) 요청만 보냄 — PUT/PATCH/DELETE 등 쓰기 요청은 절대 하지 않음
  2. 노출이 확인되면 "열려있다/닫혀있다" 상태만 기록하고, 실제 데이터 내용은
     저장·출력하지 않음 (샘플 텍스트 길이만 로그에 남김)
  3. 대상 목록(targets.txt)은 팀이 사전에 합의한 후보만 넣을 것 —
     무작위 대량 스캔 금지
  4. 요청 사이 딜레이(RATE_LIMIT_DELAY)를 지켜 대상 서버에 부하를 주지 않음
  5. 열려있는 게 확인되면 스캐너 실행을 멈추고, 팀 검증 체크리스트로
     넘겨 책임있는 공개(responsible disclosure) 절차를 따를 것

[수정 이력]
  - check_firestore(): 404를 "error"가 아니라 "no_firestore"(서비스 미사용/해당없음)로 구분
  - check_storage(): 모든 버킷 후보가 404인 경우 "error"가 아니라 "no_bucket"으로 구분
  - overall_risk(): SAFE_STATUSES에 no_firestore / no_bucket 추가해서
    실제로 안전한 케이스가 UNKNOWN이 아니라 OK로 정확히 표시되도록 수정
"""

import argparse
import csv
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

RATE_LIMIT_DELAY = 1.5  # 요청 사이 최소 대기 시간(초) — 대상 서버 부하 방지
REQUEST_TIMEOUT = 10
USER_AGENT = "FirebaseConfigChecker/1.0 (+security-research; read-only)"

FIREBASE_CONFIG_PATTERNS = {
    "apiKey": re.compile(r'apiKey["\']?\s*[:=]\s*["\']([A-Za-z0-9_\-]{30,50})["\']'),
    "projectId": re.compile(r'projectId["\']?\s*[:=]\s*["\']([a-z0-9\-]{4,40})["\']'),
    "databaseURL": re.compile(r'databaseURL["\']?\s*[:=]\s*["\']https://([a-z0-9\-]+)\.(?:firebaseio\.com|[a-z0-9\-]+\.firebasedatabase\.app)["\']'),
    "storageBucket": re.compile(r'storageBucket["\']?\s*[:=]\s*["\']([a-z0-9\-]+)\.(?:appspot\.com|firebasestorage\.app)["\']'),
    "authDomain": re.compile(r'authDomain["\']?\s*[:=]\s*["\']([a-z0-9\-]+)\.firebaseapp\.com["\']'),
}


@dataclass
class ScanResult:
    target: str
    project_id: str = ""
    database_url: str = ""
    storage_bucket: str = ""
    rtdb_status: str = "not_tested"      # open / closed / no_rtdb / error
    firestore_status: str = "not_tested"  # open / closed / no_firestore / error
    storage_status: str = "not_tested"    # open / closed / no_bucket / error
    notes: list = field(default_factory=list)
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def overall_risk(self) -> str:
        SAFE_STATUSES = ("closed", "no_rtdb", "no_firestore", "no_bucket")
        if "open" in (self.rtdb_status, self.firestore_status, self.storage_status):
            return "CRITICAL - 열려있음, 즉시 스캔 중단 후 팀 보고"
        if all(s in SAFE_STATUSES for s in (self.rtdb_status, self.firestore_status, self.storage_status)):
            return "OK - 노출 없음"
        return "UNKNOWN - 재확인 필요"


def fetch(url: str) -> requests.Response | None:
    try:
        resp = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        return resp
    except requests.RequestException as exc:
        print(f"  [!] 요청 실패: {url} ({exc})", file=sys.stderr)
        return None
    finally:
        time.sleep(RATE_LIMIT_DELAY)


def extract_firebase_config(page_text: str) -> dict:
    """사이트의 HTML/JS 텍스트에서 공개 Firebase 설정값만 추출.
    (apiKey/projectId 등은 공개돼도 되는 값 — 이 추출 자체는 취약점이 아님)
    """
    found = {}
    for key, pattern in FIREBASE_CONFIG_PATTERNS.items():
        m = pattern.search(page_text)
        if m:
            found[key] = m.group(1)
    return found


def guess_project_id(target: str, config: dict) -> str:
    if config.get("projectId"):
        return config["projectId"]
    if config.get("databaseURL"):
        return config["databaseURL"]
    if config.get("authDomain"):
        return config["authDomain"]
    # 마지막 수단: 대상이 이미 project-id 형태로 주어졌을 수 있음
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.netloc or parsed.path
    return host.split(".")[0]


def check_rtdb(project_id: str, result: ScanResult):
    url = f"https://{project_id}.firebaseio.com/.json?shallow=true"
    resp = fetch(url)
    if resp is None:
        result.rtdb_status = "error"
        return
    if resp.status_code == 404 or "does not exist" in resp.text.lower():
        result.rtdb_status = "no_rtdb"
    elif resp.status_code == 200 and resp.text.strip() not in ("null", ""):
        result.rtdb_status = "open"
        result.notes.append(f"RTDB shallow 응답 길이 {len(resp.text)}자 — 내용 미저장")
    elif resp.status_code in (401, 403):
        result.rtdb_status = "closed"
    else:
        result.rtdb_status = f"error(http {resp.status_code})"


def check_firestore(project_id: str, result: ScanResult):
    url = f"https://firestore.googleapis.com/v1/projects/{project_id}/databases/(default)/documents"
    resp = fetch(url)
    if resp is None:
        result.firestore_status = "error"
        return
    if resp.status_code == 200:
        result.firestore_status = "open"
        result.notes.append(f"Firestore 응답 길이 {len(resp.text)}자 — 내용 미저장")
    elif resp.status_code in (401, 403, 400):
        result.firestore_status = "closed"
    elif resp.status_code == 404:
        result.firestore_status = "no_firestore"
    else:
        result.firestore_status = f"error(http {resp.status_code})"


def check_storage(bucket_candidates: list, result: ScanResult):
    if not bucket_candidates:
        result.storage_status = "no_bucket_found"
        return
    statuses = []
    for bucket in bucket_candidates:
        url = f"https://firebasestorage.googleapis.com/v0/b/{bucket}/o?maxResults=1"
        resp = fetch(url)
        if resp is None:
            statuses.append(f"error({bucket})")
            continue
        if resp.status_code == 200:
            result.storage_status = "open"
            result.storage_bucket = bucket
            result.notes.append(f"Storage 버킷({bucket}) 목록 조회(1건) 성공 — 파일 미다운로드")
            return  # 열려있는 걸 찾았으면 즉시 종료
        elif resp.status_code in (401, 403):
            statuses.append(f"closed({bucket})")
        else:
            statuses.append(f"error({bucket}: http {resp.status_code})")
    # 열린 버킷을 못 찾은 경우
    if any(s.startswith("closed") for s in statuses):
        result.storage_status = "closed"
    elif statuses and all("http 404" in s for s in statuses):
        result.storage_status = "no_bucket"
    else:
        result.storage_status = "error(" + " | ".join(statuses) + ")"


def scan_target(target: str) -> ScanResult:
    result = ScanResult(target=target)
    print(f"\n[*] 대상 확인 중: {target}")

    # 1. 대상이 웹페이지 URL이면 JS/HTML에서 Firebase 설정 추출
    config = {}
    if target.startswith("http"):
        resp = fetch(target)
        if resp is not None and resp.status_code == 200:
            config = extract_firebase_config(resp.text)

    project_id = guess_project_id(target, config)
    result.project_id = project_id
    result.database_url = config.get("databaseURL", "")

    # storageBucket: JS에서 직접 찾은 값이 있으면 그것만, 없으면 신형/구형 이름 둘 다 시도
    if config.get("storageBucket"):
        bucket_candidates = [config["storageBucket"]]
    else:
        bucket_candidates = [
            f"{project_id}.firebasestorage.app",  # 최근(2024+) 기본 형식
            f"{project_id}.appspot.com",           # 예전 기본 형식
        ]
    result.storage_bucket = bucket_candidates[0]

    print(f"    project_id 추정: {project_id}")

    # 2. 읽기 전용 체크 3종
    check_rtdb(project_id, result)
    print(f"    RTDB: {result.rtdb_status}")

    check_firestore(project_id, result)
    print(f"    Firestore: {result.firestore_status}")

    check_storage(bucket_candidates, result)
    print(f"    Storage: {result.storage_status}")

    risk = result.overall_risk()
    print(f"    => {risk}")
    if risk.startswith("CRITICAL"):
        print("    [!!!] 열린 항목 발견 — 이 대상은 여기서 스캔을 멈추고 팀 체크리스트로 넘기세요.")

    return result


def load_targets(path: str) -> list:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def save_csv(results: list, out_path: str):
    fields = [
        "scanned_at", "target", "project_id", "database_url", "storage_bucket",
        "rtdb_status", "firestore_status", "storage_status", "overall_risk", "notes",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "scanned_at": r.scanned_at,
                "target": r.target,
                "project_id": r.project_id,
                "database_url": r.database_url,
                "storage_bucket": r.storage_bucket,
                "rtdb_status": r.rtdb_status,
                "firestore_status": r.firestore_status,
                "storage_status": r.storage_status,
                "overall_risk": r.overall_risk(),
                "notes": " | ".join(r.notes),
            })


def main():
    parser = argparse.ArgumentParser(description="Firebase 설정 오류 읽기 전용 스캐너")
    parser.add_argument("targets_file", help="한 줄에 하나씩: 웹사이트 URL 또는 Firebase project-id")
    parser.add_argument("-o", "--output", default="scan_results.csv", help="결과 CSV 저장 경로")
    args = parser.parse_args()

    targets = load_targets(args.targets_file)
    print(f"총 {len(targets)}개 대상 스캔 시작 (읽기 전용, 요청 간 {RATE_LIMIT_DELAY}초 대기)")

    results = [scan_target(t) for t in targets]

    save_csv(results, args.output)
    print(f"\n결과 저장 완료: {args.output}")

    open_count = sum(1 for r in results if r.overall_risk().startswith("CRITICAL"))
    if open_count:
        print(f"\n⚠️  {open_count}건에서 노출 가능성 발견 — 팀 검증 체크리스트로 넘겨서 2차 검증 진행하세요.")
        print("   (이 스캐너는 존재 여부만 확인합니다. 데이터 다운로드/저장은 하지 않았습니다.)")


if __name__ == "__main__":
    main()
