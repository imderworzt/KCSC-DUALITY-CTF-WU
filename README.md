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

## NoHarmAtAll

### Bài này sử dụng 1 kĩ thuật tên là `Process Ghosting` thông qua bài viết trên [hackercoolmagazine.com](https://hackercoolmagazine.com/process-ghosting-explained/), ta có các bước của kỹ thuật này như sau:

 ```
 - Tạo một tệp tạm: Kẻ tấn công tạo một tệp trên đĩa.

 - Đặt trạng thái chờ xóa (Delete-pending): Sử dụng hàm hệ thống NtSetInformationFile, tệp được đánh dấu là sẽ bị xóa ngay khi đóng handle (tay cầm tệp).

 - Ghi mã độc vào tệp: Payload (mã độc) được ghi vào tệp này. Do tệp đang ở trạng thái chờ xóa, các trình quét bên ngoài không thể mở nó.

 - Tạo Image Section: Tạo một phân vùng bộ nhớ (image section) từ tệp này. Đây là bước chuẩn bị để chạy chương trình.

 - Đóng handle và xóa tệp: Khi handle của tệp được đóng, hệ điều hành Windows sẽ thực sự xóa tệp khỏi đĩa cứng.

 - Chạy tiến trình: Tiến trình được tạo ra từ "Image Section" đã lưu trong bộ nhớ trước đó. Lúc này, tiến trình đang chạy nhưng tệp nguồn trên đĩa không còn tồn tại nữa.
```

Giờ vào chương trình chính thôi

### Chapter 1

Sử dụng 7zip để lấy file M1Exe ra và đưa vào IDA

<img width="1500" height="722" alt="ida_wqOHw2KdPC" src="https://github.com/user-attachments/assets/d89b086a-e086-4aaf-a624-5de7a2e47a4b" />

Hàm Main có tói hơn 700 dòng là khai báo biến, chứng tỏ khả năng hàm này bị làm rối nặng rồi, đưa lên AI cho nó gỡ rối ta thu được:

```
int main(void)
 {
     // 1) Nạp ntdll và lấy các API ntdll cần thiết.
     //    Đây là phần chuẩn bị để có thể tạo process, tạo thread, và dựng tham số process.
     resolve_ntdll_exports();

     // 2) Lấy resource nhúng trong binary, giải mã nó thành một PE blob.
     //    Blob này là payload thật, không phải dữ liệu rác.
     //    Volume serial / các hằng số trong file chỉ dùng làm entropy để làm khó phân tích.
     BYTE *blob = load_and_decrypt_resource(&blob_len, /* seed/entropy */ 0);
     if (!blob)
         return 1;

     // 3) Tạo file tạm trong thư mục temp.
     //    Tên file là "system_cache.tmp", đúng theo string nằm trong binary.
     GetTempPathA(sizeof(temp_path), temp_path);
     strcat_s(temp_path, sizeof(temp_path), "system_cache.tmp");

     // 4) Ghi blob ra file tạm và tạo section từ file đó.
     //    Đây là bước chuẩn bị để map payload sang process đích.
     HANDLE backing = write_blob_to_temp_file_and_make_section(temp_path, blob, blob_len);
     if (!backing)
         goto cleanup;

     // 5) Tạo process đích từ section.
     //    Kiểu này giống process hollowing / section-based injection.
     HANDLE process = NULL;
     NtCreateProcessEx(&process, PROCESS_ALL_ACCESS, NULL, (HANDLE)-1, 4, backing, NULL, NULL, FALSE);
     if (!process)
         goto cleanup;

     // 6) Đọc thông tin process đích.
     //    NtQueryInformationProcess trả về ProcessBasicInformation,
     //    từ đó lấy được PEB address của process đích.
     PROCESS_BASIC_INFORMATION pbi = {0};
     ULONG ret_len = 0;
     NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(pbi), &ret_len);

     // 7) Đọc PEB của process đích.
     //    Hàm helper sub_140002A50 dùng NtReadVirtualMemory để lấy dữ liệu PEB.
     //    Mục đích là kiểm tra và chuẩn bị cho bước patch tham số process.
     BYTE peb_copy[0x1B8] = {0};
     if (!read_remote_peb(process, &pbi, peb_copy))
         goto cleanup;

     // 8) Dựng ProcessParameters trong process đích.
     //    Hàm helper sub_1400050E0:
     //    - lấy environment của máy hiện tại
     //    - cấp phát bộ nhớ remote bằng VirtualAllocEx
     //    - ghi environment vào process đích bằng WriteProcessMemory
     //    - patch pointer vào PEB / ProcessParameters
     if (!setup_remote_process_parameters(process, &pbi))
         goto cleanup;

     // 9) Lấy entrypoint của PE blob.
     //    Cách đọc này là chuẩn PE:
     //    e_lfanew ở offset 0x3C, rồi OptionalHeader.AddressOfEntryPoint ở +0x28.
     DWORD e_lfanew = *(DWORD *)(blob + 0x3C);
     DWORD entry_rva = *(DWORD *)(blob + e_lfanew + 0x28);

     // 10) Tính entrypoint trong process đích và tạo thread từ đó.
     //     Đây là điểm bắt đầu chạy payload trong process mới.
     BYTE *remote_image_base = *(BYTE **)&peb_copy[0x10];
     void *remote_entry = remote_image_base + entry_rva;
     NtCreateThreadEx(&thread, 0x1FFFFF, NULL, process, remote_entry, NULL, FALSE, 0, 0, 0, NULL);

cleanup:
     // 11) Dọn dẹp.
     if (thread) CloseHandle(thread);
     if (process) CloseHandle(process);
     if (backing) CloseHandle(backing);
     if (blob) VirtualFree(blob, 0, MEM_RELEASE);
     return 0;
  }
```

Tiếp theo, cho AI gỡ rối 3 hàm sub_1400012F0, sub_1400002F0 và sub_1400041E0 rồi bảo AI tóm tắt ta thu được:

```
1. main khởi tạo các API của ntdll, rồi gọi sub_1400012F0 để lấy payload đã nhúng trong resource .
2. sub_1400012F0 đọc resource id=0x65, type=0xA, sau đó:
     - lấy volume serial của ổ C:\ bằng GetVolumeInformationA,
     - dùng 3 bytes cấp thấp làm thành key 4 bytes,
     - giải mã base64,
     - giải mã tiếp bằng biến thể RC4,
     - kiểm tra header MZ.
 3. Nếu payload hợp lệ, main gọi sub_1400041E0 để ghi blob ra file tạm, đánh dấu delete-on-close, rồi tạo section từ
    file đó.
 4. main tiếp tục tạo process đích từ section, đọc PEB của process đích qua sub_140002A50, rồi gọi sub_1400050E0 để
    dựng ProcessParameters và patch PEB.
 5. Cuối cùng NtCreateThreadEx được gọi để nhảy vào entrypoint của image đã map và chạy payload.
```

Thông qua gợi ý: Maybe the file was targeted for pbvm, not me? What information is different between us? Ta có thể hiểu thứ chúng ta cần tìm trong file này là Volume serial ổ C của anh pbvm

Kiểm tra hàm sub_1400012F0 (gỡ rối bởi AI)

```
void *load_and_decrypt_resource(size_t *out_len)
{
    HRSRC res = FindResourceA(NULL, (LPCSTR)0x65, (LPCSTR)0x0A); // RT_RCDATA
    if (!res)
        return NULL;

    HGLOBAL hres = LoadResource(NULL, res);
    DWORD raw_len = SizeofResource(NULL, res);
    void *raw = LockResource(hres);
    if (!hres || !raw_len || !raw)
        return NULL;

    uint8_t *buf = VirtualAlloc(NULL, raw_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf)
        return NULL;

    memcpy(buf, raw, raw_len);

    DWORD vol_serial = 0;
    GetVolumeInformationA("C:\\", NULL, 0, &vol_serial, NULL, NULL, NULL, 0);

    uint8_t key[4];
    derive_key_from_volume_serial(vol_serial, key); // thứ tự byte bị decompiler biểu diễn hơi rối

    DWORD decoded_len = raw_len;
    if (!CryptStringToBinaryA((LPCSTR)buf, raw_len, 1, buf, &decoded_len, NULL, NULL))
        return NULL;

    rc4_like_crypt_inplace(buf, decoded_len, key, 4);

    if (*(uint16_t *)buf != 0x5A4D) // "MZ"
        return NULL;

    *out_len = decoded_len;
    return buf;
}
```

(LPCSTR)0x0A -> RT_RCDATA

Trước tiên, ta sử dụng Process Hacker để dump RT_RCDATA ra 1 file .bin

<img width="1681" height="991" alt="GZpHUFP6vi" src="https://github.com/user-attachments/assets/87571b36-03b4-4643-bef4-ff6b94301e52" />

Sau đó decrypt base64 dữ liệu trong đó

Cuối cùng sử dụng script bruteforce sau, target output sẽ là một file PE file với:

```
- offset 0x00: MZ
- offset e_lfanew: PE\0\0
```

Script:

```
#include <bits/stdc++.h>
#include <atomic>
#include <thread>
#include <mutex>
using namespace std;

static vector<uint8_t> ct;
static atomic<uint32_t> next_start{0};
static atomic<bool> found{false};
static atomic<uint32_t> found_serial{0};
static mutex print_mtx;

static inline uint16_t rd16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static inline uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0]
        | ((uint32_t)p[1] << 8)
        | ((uint32_t)p[2] << 16)
        | ((uint32_t)p[3] << 24);
}

static inline void make_key(uint32_t serial24, uint8_t key[4]) {
    // Code gốc: VolumeSerialNumber &= 0xFFFFFF
    // Sau đó build key dạng big-endian 4 byte.
    // Vì đã mask 24-bit nên byte đầu luôn là 0.
    key[0] = 0;
    key[1] = (uint8_t)((serial24 >> 16) & 0xff);
    key[2] = (uint8_t)((serial24 >> 8) & 0xff);
    key[3] = (uint8_t)(serial24 & 0xff);
}

static inline void rc4_init(uint8_t S[256], const uint8_t key[4]) {
    for (int i = 0; i < 256; i++) {
        S[i] = (uint8_t)i;
    }

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i & 3]) & 0xff;
        swap(S[i], S[j]);
    }
}

static bool check_candidate(uint32_t serial24) {
    uint8_t key[4];
    make_key(serial24, key);

    uint8_t S[256];
    rc4_init(S, key);

    int i = 0;
    int j = 0;

    auto decrypt_next = [&](size_t pos) -> uint8_t {
        i = (i + 1) & 0xff;
        j = (j + S[i]) & 0xff;
        swap(S[i], S[j]);

        uint8_t k = S[(S[i] + S[j]) & 0xff];
        return (uint8_t)(ct[pos] ^ k);
    };

    if (ct.size() < 0x200) return false;

    uint8_t head[0x1200];
    size_t have = 0;

    // Early reject cực nhanh: chỉ decrypt 2 byte đầu.
    head[have] = decrypt_next(have);
    if (head[0] != 'M') return false;
    have++;

    head[have] = decrypt_next(have);
    if (head[1] != 'Z') return false;
    have++;

    // Nếu qua được MZ thì mới decrypt tới 0x40 để lấy e_lfanew.
    for (; have < 0x40; have++) {
        head[have] = decrypt_next(have);
    }

    uint32_t e_lfanew = rd32(head + 0x3c);

    if (e_lfanew < 0x40 || e_lfanew > 0x1000) {
        return false;
    }

    size_t need = (size_t)e_lfanew + 0x30;
    if (need > sizeof(head) || need > ct.size()) {
        return false;
    }

    for (; have < need; have++) {
        head[have] = decrypt_next(have);
    }

    if (head[e_lfanew] != 'P' ||
        head[e_lfanew + 1] != 'E' ||
        head[e_lfanew + 2] != 0 ||
        head[e_lfanew + 3] != 0) {
        return false;
    }

    uint16_t machine = rd16(head + e_lfanew + 4);
    uint16_t sections = rd16(head + e_lfanew + 6);
    uint16_t opt_size = rd16(head + e_lfanew + 20);

    if (machine != 0x8664 && machine != 0x14c) {
        return false;
    }

    if (sections < 1 || sections > 20) {
        return false;
    }

    if (opt_size != 0xF0 && opt_size != 0xE0) {
        return false;
    }

    return true;
}

static vector<uint8_t> rc4_full(uint32_t serial24) {
    uint8_t key[4];
    make_key(serial24, key);

    uint8_t S[256];
    rc4_init(S, key);

    vector<uint8_t> out(ct.size());

    int i = 0;
    int j = 0;

    for (size_t n = 0; n < ct.size(); n++) {
        i = (i + 1) & 0xff;
        j = (j + S[i]) & 0xff;
        swap(S[i], S[j]);

        uint8_t k = S[(S[i] + S[j]) & 0xff];
        out[n] = (uint8_t)(ct[n] ^ k);
    }

    return out;
}

static void worker(uint32_t chunk_size) {
    const uint32_t LIMIT = 0x1000000;

    while (!found.load(memory_order_relaxed)) {
        uint32_t start = next_start.fetch_add(chunk_size);

        if (start >= LIMIT) {
            return;
        }

        uint32_t end = start + chunk_size;
        if (end > LIMIT) {
            end = LIMIT;
        }

        for (uint32_t s = start; s < end; s++) {
            if (found.load(memory_order_relaxed)) {
                return;
            }

            if (check_candidate(s)) {
                bool expected = false;
                if (found.compare_exchange_strong(expected, true)) {
                    found_serial.store(s);

                    lock_guard<mutex> lock(print_mtx);
                    uint8_t key[4];
                    make_key(s, key);

                    cout << "[+] FOUND\n";
                    cout << "[+] serial24 = 0x"
                         << hex << setw(6) << setfill('0') << s << dec << "\n";

                    cout << "[+] key = ";
                    for (int i = 0; i < 4; i++) {
                        cout << hex << setw(2) << setfill('0') << (int)key[i];
                    }
                    cout << dec << "\n";
                }
                return;
            }
        }

        if ((start & 0xFFFFF) == 0) {
            lock_guard<mutex> lock(print_mtx);
            cerr << "[*] tried up to 0x"
                 << hex << setw(6) << setfill('0') << end << dec << "\n";
        }
    }
}

int main(int argc, char **argv) {
    string in_file = "dump.enc";
    string out_file = "dump_NEW.exe";

    if (argc >= 2) in_file = argv[1];
    if (argc >= 3) out_file = argv[2];

    ifstream f(in_file, ios::binary);
    if (!f) {
        cerr << "[-] cannot open " << in_file << "\n";
        return 1;
    }

    ct.assign(istreambuf_iterator<char>(f), istreambuf_iterator<char>());

    cout << "[+] input: " << in_file << "\n";
    cout << "[+] encrypted size: " << ct.size() << "\n";

    unsigned int nthreads = thread::hardware_concurrency();
    if (nthreads == 0) nthreads = 4;

    // Có thể chỉnh lên 0x20000 nếu muốn ít overhead hơn.
    uint32_t chunk_size = 0x4000;

    cout << "[+] threads: " << nthreads << "\n";
    cout << "[+] brute range: 0x000000 -> 0xFFFFFF\n";

    vector<thread> threads;
    auto t0 = chrono::high_resolution_clock::now();

    for (unsigned int i = 0; i < nthreads; i++) {
        threads.emplace_back(worker, chunk_size);
    }

    for (auto &t : threads) {
        t.join();
    }

    auto t1 = chrono::high_resolution_clock::now();
    double sec = chrono::duration<double>(t1 - t0).count();

    if (!found.load()) {
        cout << "[-] no valid PE found\n";
        cout << "[+] elapsed: " << sec << " sec\n";
        return 1;
    }

    uint32_t s = found_serial.load();
    vector<uint8_t> pt = rc4_full(s);

    ofstream o(out_file, ios::binary);
    o.write((const char *)pt.data(), (streamsize)pt.size());
    o.close();

    uint32_t e_lfanew = rd32(pt.data() + 0x3c);

    cout << "[+] wrote: " << out_file << "\n";
    cout << "[+] first 16 bytes: ";
    for (int i = 0; i < 16 && i < (int)pt.size(); i++) {
        cout << hex << setw(2) << setfill('0') << (int)pt[i];
    }
    cout << dec << "\n";

    cout << "[+] e_lfanew: 0x" << hex << e_lfanew << dec << "\n";
    cout << "[+] PE sig: "
         << (char)pt[e_lfanew]
         << (char)pt[e_lfanew + 1]
         << "\\x00\\x00\n";

    cout << "[+] elapsed: " << sec << " sec\n";

    return 0;
}
```

Sau khi chạy

<img width="979" height="512" alt="ConsolePauser_wv74zsuS1A" src="https://github.com/user-attachments/assets/a754db78-15ba-477b-94ce-f0cc20a30daf" />

Mở file exe trong ida, thấy segment upx

<img width="390" height="106" alt="ida_Hr7DWu8c6I" src="https://github.com/user-attachments/assets/8e775584-13e8-41ae-aa13-3bd2bcb5fd31" />

Ta decompress, sau đó đưa lên ida xem

### Chapter 2

Hàm Winmain có gọi nhiều lần hàm sau:
```
sub_140001000(_41_4%_fg_199, 12);
sub_140001000(v18, 14);
sub_140001000(v19, 14);
sub_140001000(v17, 13);
sub_140001000(v21, 18);
sub_140001000(v20, 12);
sub_140001000(v16, 12);
```

Nội dung hàm sub_140001000:

```
__int64 __fastcall sub_140001000(__int64 a1, unsigned int i_1)
{
  __int64 i_2; // rax
  int i; // [rsp+0h] [rbp-18h]

  for ( i = 0; ; ++i )
  {
    i_2 = i_1;
    if ( i >= (int)i_1 )
      break;
    *(_BYTE *)(a1 + i) ^= 0x55u;
  }
  return i_2;
}
```

Hàm này xor bytes với 0x55

Ta viết script xor lại để thấy out put các lần gọi hàm kia

```
from struct import pack

def xor55(data: bytes) -> bytes:
    return bytes(b ^ 0x55 for b in data)

blocks = [
    b"41#4%<fg{199",
    pack("<Q", 0x341816063B30251A) + bytes([59, 52, 50, 48, 39, 20]),
    pack("<Q", 0x3006302134302716) + bytes([39, 35, 60, 54, 48, 20]),
    pack("<Q", 0x2730062127342106) + bytes([35, 60, 54, 48, 20]),
    pack("<Q", 0x27300630263A3916) + bytes([35, 60, 54, 48, 29]) + b"4;190",
    pack("<Q", 0x232730063B30251A) + bytes([60, 54, 48, 20]),
    pack("<Q", 0x27373C1931343A19) + bytes([52, 39, 44, 20]),
]

for i, enc in enumerate(blocks, 1):
    dec = xor55(enc)
    print(f"{i}: {dec.decode('ascii')}")
```

Output:

<img width="482" height="131" alt="cmd_vlzQkVRmko" src="https://github.com/user-attachments/assets/511f8655-275c-4a47-936b-92e67e97b45a" />

Trong lúc check qua một vòng file này, thấy được một giá trị trong phần .data

<img width="674" height="25" alt="ida_AiYvxwmCTx" src="https://github.com/user-attachments/assets/0fe162ab-e6d1-4674-bdbd-50aa92f000ad" />

Kiểm tra hàm nó được XREF đến:

```
_BOOL8 __fastcall sub_140001050(CHAR *Buffer)
{
  DWORD dwSize; // [rsp+40h] [rbp-78h]
  LPVOID lpAddress; // [rsp+48h] [rbp-70h]
  HRSRC hResInfo; // [rsp+58h] [rbp-60h]
  HANDLE hFile; // [rsp+60h] [rbp-58h]
  HGLOBAL hResData; // [rsp+68h] [rbp-50h]
  void *Src; // [rsp+70h] [rbp-48h]
  __int64 v8; // [rsp+78h] [rbp-40h]
  void (__fastcall *v9)(CHAR *, __int64); // [rsp+80h] [rbp-38h]
  DWORD NumberOfBytesWritten; // [rsp+88h] [rbp-30h] BYREF
  __int64 v11; // [rsp+90h] [rbp-28h] BYREF
  char n33; // [rsp+98h] [rbp-20h]
  char n33_1; // [rsp+99h] [rbp-1Fh]
  char n39; // [rsp+9Ah] [rbp-1Eh]
  char n60; // [rsp+9Bh] [rbp-1Dh]
  char n55; // [rsp+9Ch] [rbp-1Ch]
  char n32; // [rsp+9Dh] [rbp-1Bh]
  char n33_2; // [rsp+9Eh] [rbp-1Ah]
  char n48; // [rsp+9Fh] [rbp-19h]
  char n38; // [rsp+A0h] [rbp-18h]
  char n20; // [rsp+A1h] [rbp-17h]
  char v22; // [rsp+A2h] [rbp-16h]

  hResInfo = FindResourceA(nullptr, (LPCSTR)0x65, (LPCSTR)0xA);
  if ( !hResInfo )
    return 0;
  hResData = LoadResource(nullptr, hResInfo);
  if ( !hResData )
    return 0;
  dwSize = SizeofResource(nullptr, hResInfo);
  Src = LockResource(hResData);
  if ( !dwSize || !Src )
    return 0;
  lpAddress = VirtualAlloc(nullptr, dwSize, 0x3000u, 4u);
  if ( !lpAddress )
    return 0;
  memcpy(lpAddress, Src, dwSize);
  sub_140001720(
    lpAddress,
    dwSize,
    PBVM,                                       // "PBVM"
    4);
  hFile = CreateFileA(Buffer, 0x40000000u, 0, nullptr, 2u, 0x80u, nullptr);
  if ( hFile == (HANDLE)-1LL )
  {
    VirtualFree(lpAddress, 0, 0x8000u);
    return 0;
  }
  else
  {
    WriteFile(hFile, lpAddress, dwSize, &NumberOfBytesWritten, nullptr);
    v11 = 0x1430393C13213006LL;
    n33 = 33;
    n33_1 = 33;
    n39 = 39;
    n60 = 60;
    n55 = 55;
    n32 = 32;
    n33_2 = 33;
    n48 = 48;
    n38 = 38;
    n20 = 20;
    v22 = 0;
    sub_140001000((__int64)&v11, 18);
    v8 = sub_140001520();
    if ( v8 )
    {
      v9 = (void (__fastcall *)(CHAR *, __int64))sub_140001340(v8, &v11);
      if ( v9 )
      {
        v9(Buffer, 6);
        sub_140001900(&v11, 19);
      }
    }
    CloseHandle(hFile);
    sub_140001900(lpAddress, dwSize);
    VirtualFree(lpAddress, 0, 0x8000u);
    return NumberOfBytesWritten == dwSize;
  }
}
```

Có vẻ nó được gọi bởi sub_140001720, kiểm tra sub_140001720:

```
__int64 __fastcall sub_140001720(_BYTE *lpAddress, DWORD dwSize, char *PBVM, unsigned int n4)
{
  __int64 dwSize_1; // rax
  unsigned int i; // [rsp+0h] [rbp-228h]
  unsigned int j; // [rsp+0h] [rbp-228h]
  unsigned int v7; // [rsp+0h] [rbp-228h]
  unsigned int v8; // [rsp+4h] [rbp-224h]
  unsigned int v9; // [rsp+4h] [rbp-224h]
  DWORD k; // [rsp+8h] [rbp-220h]
  char v11; // [rsp+Ch] [rbp-21Ch]
  char v12; // [rsp+Ch] [rbp-21Ch]
  _BYTE v13[520]; // [rsp+20h] [rbp-208h]

  for ( i = 0; i < 0x100; ++i )
  {
    v13[i] = i;
    v13[i + 256] = PBVM[i % n4];
  }
  v8 = 0;
  for ( j = 0; j < 0x100; ++j )
  {
    v8 = ((unsigned __int8)v13[j + 256] + (unsigned __int8)v13[j] + v8) % 0x100;
    v11 = v13[j];
    v13[j] = v13[v8];
    v13[v8] = v11;
  }
  v7 = 0;
  v9 = 0;
  for ( k = 0; ; ++k )
  {
    dwSize_1 = dwSize;
    if ( k >= dwSize )
      break;
    v7 = (v7 + 1) % 0x100;
    v9 = ((unsigned __int8)v13[v7] + v9) % 0x100;
    v12 = v13[v7];
    v13[v7] = v13[v9];
    v13[v9] = v12;
    lpAddress[k] ^= v13[((unsigned __int8)v13[v9] + (unsigned __int8)v13[v7]) % 256];
  }
  return dwSize_1;
}
```

Kết luận: RC4 với key là PBVM

Ta cũng thấy (LPCSTR)0xA trong dòng trên ở hàm sub_140001050

```
hResInfo = FindResourceA(nullptr, (LPCSTR)0x65, (LPCSTR)0xA);
```

Có vẻ khả năng chúng ta sẽ lấy RT_RCDATA của file này đi decrypt RC4 với key là PBVM rồi

Thực hiện nó trên cyberchef

<img width="1532" height="970" alt="n7RGqblQNC" src="https://github.com/user-attachments/assets/b77c2aa9-8da6-476c-a11b-51c484f60e81" />

Có vẻ nó đã đúng định dạng của 1 file PE, ta lưu nó xuống với đuôi là .exe luôn

<img width="432" height="181" alt="brave_inzSxlfDJF" src="https://github.com/user-attachments/assets/b9255dd5-feb8-475a-841c-952c256de42e" />

Khi mở trong IDA, file không có hàm main, mà chức năng quan trọng của nó được lưu trong hàm Function

<img width="955" height="712" alt="ida_U6XMUF9gPR" src="https://github.com/user-attachments/assets/13bf97f1-30e9-444f-8931-facc87e1c2c1" />

### Chapter 3:

Mở đầu, AI đọc hàm Function, nó chỉ ra:

```
- Chỉ xử lý một notify class cụ thể (Argument1 == 1).
- Kiểm tra Argument2 có hợp lệ hay không.
- Dùng CmCallbackGetKeyObjectIDEx để lấy full path của registry key.
- Chỉ cho đi tiếp nếu key nằm dưới:
    - \REGISTRY\MACHINE\SOFTWARE\KCSC
- Đồng thời kiểm tra tên value có đúng là:
    - INPUT_FLAG
- Nếu đúng cả key lẫn value name, nó gọi sub_140001250(...) để xác minh dữ liệu bên trong.
- Nếu xác minh thành công:
    - trả về 0
    - và gọi tiếp sub_140001490(...), hàm này giải mã tên một routine kernel rồi gọi nó qua MmGetSystemRoutineAddress
- Nếu xác minh thất bại:
    - trả về 0xC000006A tức STATUS_WRONG_PASSWORD
```

Trong này ta cũng thấy được FLAG hay KCSC, khả năng đây là phần kiểm tra cuối rồi

Vì hàm sub_140001250 là hàm kiểm tra, mình xem mã giả của hàm

```
bool __fastcall sub_140001250(_WORD *i_1, unsigned int n2, int a3)
{
  int v4; // ecx
  _WORD *i; // rax
  unsigned int n0xE1; // edi
  char v7; // r13
  __int64 n0xE1_1; // rax
  char v9; // bl
  char v10; // r10
  unsigned int n0xC0; // r9d
  char v12; // r11
  char v13; // r8
  char v14; // dl
  char v15; // cl
  char v16; // bl
  __int64 v18; // [rsp+20h] [rbp-138h]
  _BYTE Source1[240]; // [rsp+30h] [rbp-128h] BYREF

  if ( a3 == 1 && i_1 && n2 >= 2 && (n2 & 1) == 0 && (n2 & 0xFFFFFFFE) == 0x1C4 && !i_1[225] )
  {
    v4 = 0;
    for ( i = i_1; *i <= 0x7Fu; ++i )
    {
      if ( (unsigned int)++v4 >= 0xE1 )
      {
        n0xE1 = 0;
        v7 = -89;
        v18 = 0;
        do
        {
          n0xE1_1 = 0;
          v9 = v7 ^ (61 * n0xE1 + 31);
          do
          {
            if ( (_DWORD)n0xE1_1 )
              v10 = Source1[(unsigned int)(n0xE1_1 - 1)];
            else
              v10 = n0xE1 + 90;
            n0xC0 = 0;
            v12 = LOBYTE(i_1[n0xE1_1])
                ^ byte_140002500[((_BYTE)n0xE1_1 + (_BYTE)n0xE1 + 2 * (_BYTE)n0xE1_1) & 7]
                ^ (7 * n0xE1 + 11 * n0xE1_1);
            v9 += v10 + v12;
            do
            {
              v13 = v10 ^ n0xC0;
              v14 = 29 * n0xC0;
              v15 = n0xC0++ + 99;
              v9 = (n0xE1_1 + v15) ^ __ROR1__(v12 + 7 * n0xE1_1 + 13 * n0xE1 + v14 + v13 + v9, 7);
            }
            while ( n0xC0 < 0xC0 );
            n0xE1_1 = (unsigned int)(n0xE1_1 + 1);
          }
          while ( (unsigned int)n0xE1_1 <= n0xE1 );
          v16 = byte_140002500[(v18 & 7) + 8] ^ v9;
          Source1[v18] = v16;
          v7 += n0xE1++ + v16;
          ++v18;
        }
        while ( n0xE1 < 0xE1 );
        return RtlCompareMemory(Source1, &Source2_, 0xE1u) == 225;
      }
    }
  }
  return 0;
}
```

Source1 ở đây có vẻ cần là flag thật, đi qua các hàm xử lý với xự tham gia của byte_140002500 rồi so sánh với Source2_, ta lấy 2 giá trị đã biết và viết script bruteforce flag

<img width="760" height="142" alt="ida_iVnmqBn4ml" src="https://github.com/user-attachments/assets/55e814e5-3948-44f0-9d60-b1ddca20cae6" />

```
import sys

sys.setrecursionlimit(10000)

KEY = bytes.fromhex("423719a55ce17328914fd2337ac518ee")
TARGET = bytes.fromhex("""
ef3e847146fe6087eebfaa959d1227f3fdacc01a7bba01064a554bb8f38d0fa4
a4dd8c88ab3e2c744191559dc6ff54ad384d808013896499a0c44b168a4c6f10
1d05c34b8bf1ae4b1c9505d56eb75a07be7c263be0f88943945e5f540d831672
f073b6c45cc1fbcd404276d71866c1394be12a1d3cb58b8f7e081e4959159bcd
28ff2884d87ef1581502b82c8e560856f834f1a15665ce9cabd2068a917b3af0
804d304713473e132242d4ff51058cec9c3fde32374eb4952e859c221917632e
dc3afb363eb6a1a11e938061ab300abc89bfe9645928a24e56187e414b61dab29b
""")

N = len(TARGET)

ROL1 = [((i << 1) | (i >> 7)) & 0xff for i in range(256)]
A = [[(j + c + 99) & 0xff for c in range(192)] for j in range(N)]
M = [[(29 * c + (v10 ^ c)) & 0xff for c in range(192)] for v10 in range(256)]

prefix = b"KCSC{"
P = [None] * N
for i, b in enumerate(prefix):
    P[i] = b

# v7 before each outer round depends only on TARGET, not on the candidate flag bytes.
v7_before = [0] * (N + 1)
v7_before[0] = 0xA7
for i in range(N):
    v7_before[i + 1] = (v7_before[i] + i + TARGET[i]) & 0xff

def compute_stage_state(k):
    state = (v7_before[k] ^ ((61 * k + 31) & 0xff)) & 0xff
    for j in range(k):
        inp = P[j]
        v10 = ((k + 90) & 0xff) if j == 0 else TARGET[j - 1]
        v12 = (inp ^ KEY[(k + 3 * j) & 7] ^ ((7 * k + 11 * j) & 0xff)) & 0xff
        x = (state + v10 + v12) & 0xff
        const = (v12 + 7 * j + 13 * k) & 0xff
        Aj = A[j]
        Mv = M[v10]
        for c in range(192):
            x = Aj[c] ^ ROL1[(x + const + Mv[c]) & 0xff]
        state = x
    return state

def check_byte(k, state, b):
    v10 = ((k + 90) & 0xff) if k == 0 else TARGET[k - 1]
    v12 = (b ^ KEY[(k + 3 * k) & 7] ^ ((7 * k + 11 * k) & 0xff)) & 0xff
    x = (state + v10 + v12) & 0xff
    const = (v12 + 7 * k + 13 * k) & 0xff
    Ak = A[k]
    Mv = M[v10]
    for c in range(192):
        x = Ak[c] ^ ROL1[(x + const + Mv[c]) & 0xff]
    return ((x ^ KEY[8 + (k & 7)]) & 0xff) == TARGET[k]

# Printable first, then the rest of 7-bit range.
cand_order = list(range(0x20, 0x7f)) + list(range(0x00, 0x20)) + [0x7f]

def dfs(k):
    if k == N:
        flag = bytes(P).decode("latin1")
        print(flag)
        return True

    state = compute_stage_state(k)

    if P[k] is not None:
        return check_byte(k, state, P[k]) and dfs(k + 1)

    for b in cand_order:
        if check_byte(k, state, b):
            P[k] = b
            if dfs(k + 1):
                return True
            P[k] = None
    return False

if __name__ == "__main__":
    if not dfs(0):
        print("not found")
```

Output:

<img width="973" height="65" alt="cmd_wGMhPQ2H6r" src="https://github.com/user-attachments/assets/06fc3f72-62dd-4e9d-9685-45712c7f8763" />

KCSC{w3lc0m3_y0u_t0_th1s_k3rn3l_l4nd_cha11eng3.I_h0p3_th3_fl49_15_n07_t00_l0ng_s0_that_y0u_can_bru7e-forc3_it.L00k_back_and_s33_1f_y0u_learnt_proc3ss_gh0s71n9_and_dr1v3r_r3v3rsing.C0ngratulati0ns_and_w1sh_y0u_a11_th3_b3st!!!}
