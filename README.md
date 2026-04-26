# KCSC-DUALITY-CTF-WU

*Hiện tại thì WU này bao gồm những bài mình làm được trong thời gian giải diễn ra, WU của những bài còn lại sẽ được cập nhật bên dưới trong thời gian sớm nhất :-))*

## brainrot

<img width="390" height="342" alt="brave_iQOUHr3Scn" src="https://github.com/user-attachments/assets/9b6c2461-7bd1-4302-9a16-c018c49d5e58" />

Đưa vào IDA, có 3 thứ làm mình chú ý đến bao gồm:

<img width="278" height="246" alt="ida_62QqYu7nGH" src="https://github.com/user-attachments/assets/a3f75c74-3131-41f9-8c8e-9d6357813e28" />

1 chuỗi giá trị (Buf2) cùng với phần nhập input

<img width="302" height="95" alt="ida_eoussJflZ1" src="https://github.com/user-attachments/assets/8c1a6e53-d9f8-41a5-9054-ffdc76853264" />

lea Buf2 để so sánh với input sau xử lý: Buf1

<img width="666" height="148" alt="ida_hzPgYVs38G" src="https://github.com/user-attachments/assets/afc31a18-2d1d-4113-b1c6-c1963ebd5b44" />

Phần code được làm rối rất dài, dùng để xào nấu input

Để làm bài này, chỉ có thể là brute ra flag thôi

Script brute-force:

```
import os
import tempfile
import subprocess

EXE = r"D:\ctf\last_dance_da_0_solve\brainrot.exe"
TMP_EXE = os.path.join(tempfile.gettempdir(), "brainrot_brutepatch.exe")

 # từ IDA: main+0x9A => mov r8d, 20h (độ dài memcmp), file offset imm32 = 0x87C
IMM_OFF = 0x87C
FLAG_LEN = 32

CHARSET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "{}_-!@#$%^&*().?:;"
)

def run_check(exe_path: str, s: str) -> str:
    p = subprocess.run(
        [exe_path],
        input=(s + "\n").encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return p.stdout.decode(errors="ignore")

with open(EXE, "rb") as f:
    original = f.read()

known = ""
for i in range(FLAG_LEN):
    patched = bytearray(original)
    patched[IMM_OFF:IMM_OFF + 4] = (i + 1).to_bytes(4, "little")  # memcmp len = i+1
    with open(TMP_EXE, "wb") as f:
        f.write(patched)

    found = False
    for ch in CHARSET:
        candidate = known + ch + ("A" * (FLAG_LEN - i - 1))
        out = run_check(TMP_EXE, candidate)
        if "Correct!" in out:
            known += ch
            print(f"[+] pos {i+1:02d}: {ch} -> {known}")
            found = True
            break

    if not found:
        raise RuntimeError(f"Không tìm được ký tự tại vị trí {i+1}, current={known}")

print("[=] candidate:", known)
print(run_check(EXE, known))
```

## medium antidebug revenge

<img width="793" height="812" alt="brave_4v23csjjak" src="https://github.com/user-attachments/assets/d41f7a22-58f5-4cd3-b2b7-fc0246ee9445" />

Vì đã làm một bài dạng này trong đợt training và được viết bởi cùng 1 người nên mình kiểm tra phần thư viện trước

<img width="722" height="200" alt="ida_Lg2fysi2Xq" src="https://github.com/user-attachments/assets/0804ed0d-5c3d-411f-9310-f5f00900ee54" />

Ahh shit, here we go again.

Có 1 target là 5f 08 6b 01 0c fd dd 6f

```
data:00007FF77A985080 unk_7FF77A985080 db  5Fh ; _            ; DATA XREF: sub_7FF77A97CBC0+2E↑o
.data:00007FF77A985081                 db    8
.data:00007FF77A985082                 db  6Bh ; k
.data:00007FF77A985083                 db    1
.data:00007FF77A985084                 db  0Ch
.data:00007FF77A985085                 db 0FDh
.data:00007FF77A985086                 db 0DDh
.data:00007FF77A985087                 db  6Fh ; o
```

Và key là `qword_7FF77A985078 dq 0C34443424140C031h`

Mình đi đặt breakpoint vào các dòng check input, nhập input các kiểu thì tìm được hàm sub_14000C700

Đọc nội dung hàm này, rút ra kết luận đây là biến thể của TEA encryption

Và như một thói quen, mình đặt breakpoint vào những chỗ có dạng như 2 bp này (sử dụng đê gọi hàm mã hóa SystemFunctionXYZ)

<img width="463" height="420" alt="ida_mwN7VUcJKB" src="https://github.com/user-attachments/assets/f70db7ee-e95c-4d8d-be07-96f5f58a260a" />

Giờ chỉ cần xem hàm mã hóa đó là gì, và thứ tự mã hóa là gì.

Sau 1 hồi debug mà không được, vì luật không cấm nên mình ném thử lên mcp (nỗ lực cuối cùng) thì có thứ tự như sau:

Input 8 kí tự, đi qua một vòng mã hóa sau đây:

RC4 -> DES decrypt -> RC4 -> TEA-variant encrypt -> DES decrypt x3 -> RC4 -> TEA-variant encrypt

Đảo ngược lại ta được password là Congrats -> Flag là KCSC{Congrats}
