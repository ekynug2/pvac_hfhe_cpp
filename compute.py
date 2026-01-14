import hashlib, struct
seed = "before bulb add critic scissors eight burden wheat radar start grid false"
h = hashlib.sha256(seed.encode()).digest()[:8]
val = struct.unpack('<Q', h)[0]
print(val)  # → likely NOT 15106144148009027601
