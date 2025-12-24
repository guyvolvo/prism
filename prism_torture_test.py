import os
import base64
import zlib
import math
import random

OUT = "prism_torture_samples"
os.makedirs(OUT, exist_ok=True)

def write(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)

# 1️⃣ Entropy exactly near threshold (should be SUSPICIOUS, not MALICIOUS)
near_entropy = (b"A" * 2048) + os.urandom(2048)
write("entropy_edge_case.bin", near_entropy)

# 2️⃣ Decoy PowerShell (benign text)
decoy_ps = b"""
This is documentation text.
The word powershell appears here,
but nothing is executed.
"""
write("powershell_decoy.txt", decoy_ps)

# 3️⃣ Nested encoding: base64(zlib(random))
nested = base64.b64encode(zlib.compress(os.urandom(1500)))
write("nested_encoded.txt", nested)

# 4️⃣ Almost PE but invalid (should be SUSPICIOUS)
almost_pe = b"MZ" + b"\x00" * 40 + b"PX\x00\x00" + os.urandom(300)
write("almost_pe.bin", almost_pe)

# 5️⃣ Polyglot bait (text + fake headers)
polyglot = (
    b"Hello World\n"
    b"%PDF-1.4\n"
    b"MZ"
    + os.urandom(200)
)
write("polyglot_bait.txt", polyglot)

# 6️⃣ Clean high structure, low entropy (must be CLEAN)
low_entropy_structured = b"\x01\x02\x03\x04" * 1024
write("structured_clean.bin", low_entropy_structured)

# 7️⃣ Small file with dangerous keywords (edge case)
tiny_macro = b"Sub AutoOpen()\nEnd Sub"
write("tiny_macro.txt", tiny_macro)

# 8️⃣ Zlib bomb attempt (safe size)
bomb = zlib.compress(b"A" * 5000)
write("compression_bomb.bin", bomb)

# 9️⃣ Header collision (PDF + PE overlap)
collision = b"%PDF-1.7\n" + b"MZ" + os.urandom(400)
write("header_collision.bin", collision)

print("[+] Prism torture samples created in", OUT)
