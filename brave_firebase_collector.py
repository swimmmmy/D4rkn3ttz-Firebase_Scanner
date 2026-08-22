"""
brave_firebase_collector.py

Brave Search API로 Firebase 후보 URL을 자동 수집하는 스크립트.

흐름:
  1. SEARCH_QUERIES 목록을 Brave Search API에 순차 질의
  2. 결과 URL 중 블로그/문서/템플릿/튜토리얼/데모 패턴 제외
  3. 기존 targets.txt(or urls.txt)와 대조해서 신규 URL만 추가
  4. 결과를 새 파일(candidates_new.txt)에 저장 → 이후 firebase_scanner.py로 스캔

사용법:
  1) 환경변수로 API 키 설정
       Windows(PowerShell): $env:BRAVE_API_KEY="여기에키"
       Windows(cmd):         set BRAVE_API_KEY=여기에키
  2) EXISTING_URLS_FILE, OUTPUT_FILE 경로를 본인 환경에 맞게 수정
  3) python brave_firebase_collector.py 실행
"""

import os
import re
import time
import json
import urllib.request
import urllib.parse

# ── 설정 ──────────────────────────────────────────────────────────
BRAVE_API_KEY = os.environ.get("BRAVE_API_KEY", "")
BRAVE_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"

# 기존에 이미 검사한 URL 목록 (중복 방지용). 없으면 빈 리스트로 시작.
EXISTING_URLS_FILE = "./input/urls.txt"

# 새로 발견한 후보를 저장할 파일. firebase_scanner.py의 targets.txt 형식에 맞춰
# 필요하면 이후에 project id를 채워 넣는 전처리 단계를 거치세요.
OUTPUT_FILE = "./input/candidates_new.txt"

# 쿼리 사이 딜레이(초). 무료 티어 rate limit 보호용.
REQUEST_DELAY_SEC = 1.2

# 결과에서 제외할 URL 패턴 (경로/쿼리 문자열 기준)
EXCLUDE_PATTERNS = [
    "blog", "docs", "tutorial", "template", "demo", "github",
    "portfolio", "example", "sample", "boilerplate", "starter",
]

# Firebase Hosting에서 실제로 쓰이는 도메인들
FIREBASE_DOMAINS = [
    "firebaseapp.com",
    "web.app",
]

# 기능 문구 기반 쿼리 (PDF의 영/한 검색식을 Firebase 도메인용으로 재사용)
FUNCTIONAL_PHRASES = [
    '("book appointment" OR "available slots" OR "reservation")',
    '("order history" OR "shopping cart" OR "track order" OR "inventory")',
    '("customer details" OR "contact management" OR "client list" OR "sales pipeline")',
    '("create project" OR "assign task" OR "team members" OR "workspace")',
    '("course progress" OR "student profile" OR "class schedule" OR "assignment")',
    '("create post" OR "new comment" OR "edit profile" OR "send message")',
    '("upload document" OR "recent files" OR "shared with me" OR "file manager")',
    '("submit response" OR "support ticket" OR "contact request" OR "feedback form")',
    '("예약하기" OR "예약 내역" OR "상담 신청")',
    '("주문 내역" OR "배송 조회" OR "장바구니")',
    '("고객 관리" OR "회원 목록" OR "문의 내역")',
]

EXCLUDE_SUFFIX = " -inurl:blog -inurl:docs -tutorial -template -github -demo"


def build_queries():
    """도메인 x 기능문구 조합으로 검색어 리스트 생성"""
    queries = []
    for domain in FIREBASE_DOMAINS:
        for phrase in FUNCTIONAL_PHRASES:
            queries.append(f"site:{domain} {phrase}{EXCLUDE_SUFFIX}")
    return queries


def brave_search(query, count=20):
    """Brave Search API 호출, 결과 URL 리스트 반환"""
    if not BRAVE_API_KEY:
        raise RuntimeError("BRAVE_API_KEY 환경변수가 설정되어 있지 않습니다.")

    params = urllib.parse.urlencode({"q": query, "count": count})
    url = f"{BRAVE_ENDPOINT}?{params}"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/json")
    req.add_header("X-Subscription-Token", BRAVE_API_KEY)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"  [ERROR] 요청 실패: {e}")
        return []

    results = data.get("web", {}).get("results", [])
    return [r.get("url", "") for r in results if r.get("url")]


def is_excluded(url):
    lower = url.lower()
    return any(pattern in lower for pattern in EXCLUDE_PATTERNS)


def load_existing_urls(path):
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def main():
    existing = load_existing_urls(EXISTING_URLS_FILE)
    print(f"기존 URL {len(existing)}개 로드 완료")

    queries = build_queries()
    print(f"총 {len(queries)}개 검색어로 수집 시작\n")

    new_urls = set()

    for i, q in enumerate(queries, 1):
        print(f"[{i}/{len(queries)}] {q[:80]}...")
        urls = brave_search(q)
        for u in urls:
            if is_excluded(u):
                continue
            if u in existing or u in new_urls:
                continue
            new_urls.add(u)
        time.sleep(REQUEST_DELAY_SEC)

    print(f"\n신규 후보 URL {len(new_urls)}개 발견")

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for u in sorted(new_urls):
            f.write(u + "\n")

    print(f"저장 완료: {OUTPUT_FILE}")
    print("이후 firebase_scanner.py 로 신규 후보들을 스캔하세요.")


if __name__ == "__main__":
    main()
