import os
import zipfile
import zlib

BASE = "prism_test_samples"
os.makedirs(BASE, exist_ok=True)

def write(path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)

# 1️⃣ Clean text file (baseline)
write(f"{BASE}/clean.txt", b"hello world\nthis is a benign file")

# 2️⃣ High entropy binary (entropy path)
write(f"{BASE}/high_entropy.bin", os.urandom(4096))

# 3️⃣ Fake embedded PE inside TXT (hidden binary detection)
write(
    f"{BASE}/embedded_pe.txt",
    b"AAAAAAA" + b"MZ" + os.urandom(2048)
)

# 4️⃣ Malformed PE (PE parser fallback)
write(
    f"{BASE}/malformed.exe",
    b"MZ\x00\x00" + os.urandom(1024)
)

# 5️⃣ Fake PDF with compressed stream (PDF carve + entropy)
pdf_stream = zlib.compress(b"powershell -enc AAAABBBBCCCC")
fake_pdf = (
    b"%PDF-1.7\n"
    b"1 0 obj\n"
    b"<<>>\n"
    b"stream\n" +
    pdf_stream +
    b"\nendstream\nendobj\n%%EOF"
)
write(f"{BASE}/fake.pdf", fake_pdf)

# 6️⃣ Office OOXML with embedded binary
with zipfile.ZipFile(f"{BASE}/macro.docx", "w") as z:
    z.writestr("word/document.xml", "<xml>test</xml>")
    z.writestr("word/vbaProject.bin", os.urandom(2048))
    z.writestr("word/embeddings/evil.bin", b"MZ" + os.urandom(1024))

print("[+] Prism sanity test files created in:", BASE)