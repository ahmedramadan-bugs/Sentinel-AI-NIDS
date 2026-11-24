"""
manual_block_check.py
---------------------------------------
نسخة مخصصة للمراقبة اليدوية بالعين (ping مستمر من تيرمنال تاني):

    PC1 (192.168.10.55) -> حظر دائم
    PC3 (192.168.10.11) -> حظر مؤقت 30 ثانية

مهم: أي حاجة تحصل (نجاح أو فشل أو Ctrl+C)، الـ finally في الآخر
هيفك حظر أي IP لسه محظور قبل ما يقفل، عشان الشبكة ماتفضلش عالقة
في نص الطريق زي ما حصل قبل كده.

شغّله من تيرمنال الأوبونتو (مش من جوه VPCS):
    python3 manual_block_check.py
"""

import time
from response_engine import ResponseEngine

PC1 = "192.168.10.55"   # حظر دائم
PC3 = "192.168.10.11"   # حظر مؤقت

TEMP_BLOCK_SECONDS = 30

# هامش أمان: نستنى شوية زيادة عن مدة الحظر المؤقت عشان نضمن
# إن التايمر الداخلي أخد فرصته الكاملة يشتغل قبل ما نتحقق
WAIT_SECONDS = TEMP_BLOCK_SECONDS + 5


def line(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def cleanup(engine):
    """يفك حظر أي IP لسه محظور، مهما حصل، قبل ما نقفل."""

    line("CLEANUP: التأكد إن كل حاجة رجعت طبيعي")

    active = engine.get_active_blocks()

    if not active:
        print("مفيش أي IP محظور - تمام.")
        return

    for b in active:
        ip = b["ip"]
        print(f"لسه محظور: {ip} -> بنفك حظره...")
        r = engine.unblock_ip(ip, source="Cleanup")
        print(r)


def main():

    engine = ResponseEngine()

    try:
        line("1) STARTUP")
        ok = engine.startup()
        print("startup ok? ->", ok)

        if not ok:
            print("فشل الاتصال بـ IOU1 - تأكد من الإعدادات في config.py")
            return

        line("2) الحالة الابتدائية")
        print("Active blocks:", engine.get_active_blocks())

        # ----------------------------------------------------
        line(f"3) حظر PC1 ({PC1}) بشكل دائم")
        r = engine.block_ip(PC1, attack="Manual Lab Test", severity="High", source="TestScript")
        print(r)
        assert r["success"] is True

        # ----------------------------------------------------
        line(f"4) حظر PC3 ({PC3}) مؤقتًا لمدة {TEMP_BLOCK_SECONDS} ثانية")
        r = engine.temp_block_ip(PC3, timeout=TEMP_BLOCK_SECONDS, attack="Manual Lab Test", source="TestScript")
        print(r)
        assert r["success"] is True

        line("الحالة دلوقتي: الاتنين محظورين")
        print("Active blocks:", engine.get_active_blocks())
        print(">> روح شوف الـ ping بتاع PC1 و PC3 دلوقتي في التيرمنالات التانية <<")

        # ----------------------------------------------------
        line(f"5) السكريبت هيستنى {WAIT_SECONDS} ثانية (تابع الـ ping بعينك دلوقتي)")

        for remaining in range(WAIT_SECONDS, 0, -5):
            print(f"   باقي {remaining} ثانية...")
            time.sleep(5 if remaining >= 5 else remaining)

        # ----------------------------------------------------
        line("6) بعد الانتظار: هل PC3 فك حظره لوحده بالتايمر؟")
        pc3_blocked = engine.is_blocked(PC3)
        print("PC3 لسه محظور؟ ->", pc3_blocked)
        assert pc3_blocked is False, "المفروض التايمر يفك حظر PC3 تلقائيًا بعد المدة"

        print("PC1 لسه محظور (متوقع، لأنه دائم)؟ ->", engine.is_blocked(PC1))
        assert engine.is_blocked(PC1) is True

        # ----------------------------------------------------
        line(f"7) فك حظر PC1 ({PC1}) يدويًا عشان ترجع الشبكة طبيعية بالكامل")
        r = engine.unblock_ip(PC1, source="TestScript")
        print(r)
        assert r["success"] is True
        assert engine.is_blocked(PC1) is False

        # ----------------------------------------------------
        line("8) الحالة النهائية (المفروض مفيش حظر خالص)")
        print("Active blocks:", engine.get_active_blocks())
        assert engine.get_active_blocks() == []

        # ----------------------------------------------------
        line("9) الإحصائيات النهائية")
        print(engine.get_stats())

        # ----------------------------------------------------
        line("10) الـ History")
        for entry in engine.get_history()[-4:]:
            print(entry)

        print("\n✅ الاختبار خلص بنجاح - كل حاجة رجعت طبيعي")

    finally:
        # يتنفذ دايمًا: نجاح، فشل assert، أو حتى Ctrl+C.
        # يضمن إننا مانسيبش أي IP محظور عالق على الراوتر.
        cleanup(engine)

        line("SHUTDOWN")
        engine.shutdown()


if __name__ == "__main__":
    main()
