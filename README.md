# 🖥️ 시스템 프로그래밍 Proxy 과제 (2025-1)

광운대학교 2025년 1학기 시스템 프로그래밍 Proxy 과제입니다.  
프록시 서버 구현을 중심으로, 파일 시스템 조작, 해시, 소켓 통신, 멀티 프로세스 및 스레드, 시그널 처리, 동기화 등 핵심 시스템 프로그래밍 개념을 실습합니다.

---

## 📁 디렉토리 구조

| 디렉토리     | 내용 요약 |
|--------------|-----------|
| `Basic/`     | Ubuntu 설치, 리눅스 명령어(`chmod`, `ps`, `grep`), `vi`, `Makefile` 작성 |
| `Proxy1-1/`  | SHA-1 해시 사용, 캐시 디렉토리 및 파일 생성, `umask`, `mkdir` |
| `Proxy1-2/`  | `readdir`로 HIT/MISS 판별, `ctime` 사용해 로그 기록 |
| `Proxy1-3/`  | `fork()` 사용, `connect`, `bye`, `quit` 명령 처리, 다중 프로세스 |
| `Proxy2-1/`  | `socket`, `bind`, `listen`, `accept` 기반 서버-클라이언트 구현 |
| `Proxy2-2/`  | HTTP 요청 처리, `Host` 파싱, 캐시 저장 및 HIT/MISS 응답 |
| `Proxy2-3/`  | `SIGCHLD`, `SIGALRM`, `SIGINT` 시그널 처리, 타임아웃 알람 |
| `Proxy3-1/`  | `semaphore`로 로그 접근 동기화, Critical Section 보호 |
| `Proxy3-2/`  | `pthread` 기반 로그 기록 스레드, TID 생성/종료 출력 |

---

## 📄 제출 형식

- `.pdf` 보고서 + 소스 코드(.c) + Makefile → `.tar.xz` 압축 제출  
- 보고서 파일명: `과제명_수강코드_학번_이름.pdf`

**보고서 구성:**  
- Introduction (과제 소개)  
- 결과 화면 및 설명  
- 고찰  
- 참고자료

---

## 📎 참고

- 모든 실습은 Ubuntu 20.04 환경 기준  
- 무단 복제 및 배포 금지
