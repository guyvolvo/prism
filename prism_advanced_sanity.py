import os
import random
import base64
import zlib

OUT = "prism_adv_samples"
os.makedirs(OUT, exist_ok=True)

def write(name, data, mode="wb"):
    with open(os.path.join(OUT, name), mode) as f:
        f.write(data)

# 1️⃣ Clean text (baseline)
write("clean.txt", b"Hello Prism\nThis is a clean file.\n")

# 2️⃣ High entropy blob (packed-like)
write("high_entropy.bin", os.urandom(4096))

# 3️⃣ Fake PE header (triggers PE heuristics but malformed)
write("fake_pe.exe",
      b"MZ" + b"\x00"*58 + b"PE\x00\x00" + os.urandom(512))

# 4️⃣ Embedded PE inside text (stream carving test)
embedded = (
    b"Normal text\n"
    b"MZ" + os.urandom(300) +
    b"PE\x00\x00" + os.urandom(300)
)
write("embedded_pe.txt", embedded)

# 5️⃣ Corrupt PDF (structural + YARA)
pdf = b"""%PDF-1.7
1 0 obj
<< /Type /Catalog >>
endobj
xref
0 2
0000000000 65535 f
trailer
<< /Root 1 0 R >>
%%EOF
"""
write("corrupt.pdf", pdf)

# 6️⃣ Obfuscated macro-like text (entropy + keywords)
macroish = b"""
Sub AutoOpen()
Dim s As String
s = "powershell -enc " & "SQBFAFgA"
End Sub
"""
write("macro_like.txt", macroish)

# 7️⃣ Compressed payload (zlib inside file)
payload = zlib.compress(os.urandom(1024))
write("compressed_payload.bin", payload)

# 8️⃣ Base64 payload (decode heuristic)
b64 = base64.b64encode(os.urandom(1024))
write("base64_blob.txt", b64)

print("[+] Advanced Prism sanity samples created in", OUT)