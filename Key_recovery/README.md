# Key Recovery - Crypto 250 - 39 solves

![image](https://user-images.githubusercontent.com/92845822/167410209-c5f6a18c-c9ea-4812-9273-5092fb48cfca.png)

Chúng ta được cung cấp 1 file OpenSSH private key bị phá hoại và nhiệm vụ là phải phục hồi lại nguyên trạng. 

![image](https://user-images.githubusercontent.com/92845822/167399716-e59e7a95-e7b8-49f1-be85-9cb0cd7f7c9e.png)

Sau khi decode toàn bộ base64 ra thì mình thấy đây là 1 file rsa key. Đây là link mình tham khảo để giải đươc câu này: [OpenSSH format](https://coolaj86.com/articles/openssh-vs-openssl-key-formats/)
Format của 1 file RSA private key: 

![image](https://user-images.githubusercontent.com/92845822/167376189-7c72b22b-638f-4e7d-9ccd-a0e98ac31306.png)

## Phân tích file ransomware.py

 ```python
 #! /usr/bin/env python3
import base64

KEY = 'id_rsa'
COR = 'id_rsa.corrupted'

with open(KEY) as pk:
    lines = list(pk)
    b64 = ''.join((line[:-1] for line in lines[1:-1]))
    bys = bytearray(base64.b64decode(b64))

# Nuke some byte ranges

OFFSET_LENGTHS = [(454 + 808, 190), (454 + 1004, 193), (454 + 1201, 193)] # Specific to this type of key, may not work for others...

for offset, length in OFFSET_LENGTHS:
    bys[offset:offset+length] = b'\0' * length

# Write out the key in the same format as the input key

HEADER = '-----BEGIN OPENSSH PRIVATE KEY-----\n'
FOOTER = '-----END OPENSSH PRIVATE KEY-----\n'
LINE_LENGTH = 70 # Excluding newline characters

corrupted_b64 = base64.b64encode(bys).decode('ascii')

with open(COR, 'w') as pk:
    pk.write(HEADER)
    pk.writelines(corrupted_b64[i:i+LINE_LENGTH] + '\n' for i in range(0, len(corrupted_b64), LINE_LENGTH))
    pk.write(FOOTER)

# Edit: MALICIOUS code commented out BELOW for your safety!
# __import__('os').remove(KEY)

print(f'***** WARNING: YOUR SSH PRIVATE KEY HAS BEEN CORRUPTED *****')
print(f'Pay me 1000 BTC to recover your corrupted private key at {COR}')
 ```
Sau khi đọc file ransom thì thấy các byte từ 1262-1452, 1458-1651, 1655-1848 bị thay bằng **NULL** . Đó có vẻ là các bytes của private key, tuy nhiên các bytes của public key nằm ở đầu nên ta có thể phục hồi được.

## Lấy các giá trị sử dụng được từ file OpenSSH PRIVATE KEY
Sử dụng lệnh ssh-keygen để lấy public key dưới dạng SSH:
> ssh-keygen -y -f id_rsa.corrupted > key.pub

![image](https://user-images.githubusercontent.com/92845822/167352018-603e044e-cf01-4673-9e09-3e645d0e0817.png)

Tới đây mình dùng python để lấy giá trị **n** và **e** từ public key. File [step1](https://github.com/Tsouth113/San-Diego/blob/main/Key_recovery/step1.py)

![image](https://user-images.githubusercontent.com/92845822/167362784-1253bd9a-7d42-417c-bcbb-5793cac52e6c.png)

Bây giờ đã có giá trị **n** nên việc đầu tiên mình làm đó là quăng vô [factordb](factordb.com) để kiểm tra xem đã bị leak các giá trị factor chưa. 

![image](https://user-images.githubusercontent.com/92845822/167366296-29dd2610-f029-45c6-a133-583994b9e993.png)

Và thật bất ngờ là nó có thiệt :). Có **p**, **q** rồi ta có thể tìm **phiN** từ đó tính **d**. Như vậy việc cần làm là tìm cách tạo được 1 file private key từ **n, e, d**

![image](https://user-images.githubusercontent.com/92845822/167400154-8ebf8a14-22e5-4a70-950b-9b5cec837153.png)

## Phục hồi file ban đầu
Sau khi tra Google một hồi mình không tìm ra cách dùng các giá trị khóa để tạo thành file OpenSSH private key tuy nhiên sau khi đọc 1 bài trên stackoverflow ([link](https://stackoverflow.com/questions/54994641/openssh-private-key-to-rsa-private-key)) thì mình tìm thấy 1 tool là [putty](https://github.com/github/putty) có thể convert được nên mình bật ubuntu chạy thử.

![image](https://user-images.githubusercontent.com/92845822/167402050-aae828c2-5093-4756-9fe6-771883a5751f.png)

Sử dụng thư viện PyCryptodome để tạo 1 file PEM từ các giá trị khóa. 

![image](https://user-images.githubusercontent.com/92845822/167402665-9f8e46f2-89a6-4ee6-9556-ab6321d583f3.png)

Chạy file [step2](https://github.com/Tsouth113/San-Diego/blob/main/Key_recovery/step2.py) để tạo ra 1 file [private key](https://github.com/Tsouth113/San-Diego/blob/main/Key_recovery/key.pem) dạng PEM rồi chạy lệnh bên dưới để bên dưới để lấy chuyển đổi sang file OpenSSH private key (-**C** để thêm comment 'SDCTF' vào file).
>puttygen -C SDCTF key.pem -O private-openssh-new -o newkey

![image](https://user-images.githubusercontent.com/92845822/167403631-4afbb923-bae4-4af0-bba3-6886c953cb23.png)

Mặc dù file bị corupted rất giống file này tuy nhiên ta cần nhớ lại format file

![image](https://user-images.githubusercontent.com/92845822/167411130-d1eb2b5d-9452-4106-9a12-eb1f62959329.png)

So sánh các bytes không bị ảnh hưởng bởi ta cũng thấy có 8 bytes khác nhau

![image](https://user-images.githubusercontent.com/92845822/167412575-9122882d-00bd-4888-b284-175e894a5b61.png)

Nên lúc này mình sẽ sao chép các bytes của file [id_rsa.corrupted]() và chỉ lấy các bytes bị mất từ file [newkey]() rồi chép vào 1 file mới sử dụng bằng đoạn code của file [ransomware.py]()

![image](https://user-images.githubusercontent.com/92845822/167408675-c81b2cbe-2976-4a03-ae1a-bd2818df1324.png)

Băm nó ra thành sha256 rồi submit là xong.

![image](https://user-images.githubusercontent.com/92845822/167402924-898b712d-5b84-43af-9286-997973ad32a8.png)

File phục hồi hoàn chỉnh: [id_rsa](https://github.com/Tsouth113/San-Diego/blob/main/Key_recovery/id_rsa)