"""
recover.py
---------------------------------------
سكريبت طوارئ: يتصل بالراوتر، يجيب أي IP محظور دلوقتي،
ويفك حظره كله. استخدمه لو حصل crash وسايب حظر عالق.
"""

from response_engine import ResponseEngine

engine = ResponseEngine()

ok = engine.startup()
print("startup ok?", ok)

if not ok:
    print("فشل الاتصال بالراوتر.")
    exit()

blocks = engine.get_active_blocks()
print("محظور دلوقتي:", blocks)

for b in blocks:
    ip = b["ip"]
    r = engine.unblock_ip(ip, source="RecoveryScript")
    print(f"فك حظر {ip} ->", r)

print("النهائي:", engine.get_active_blocks())

engine.shutdown()
