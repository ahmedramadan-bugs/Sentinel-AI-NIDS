# Sentinel-AI — WebSocket API Protocol

اتصل بـ:

```
ws://<server-ip>:8765
```

كل الرسائل في الاتجاهين JSON نصي (text frame). كل رسالة فيها حقل `type` بيحدد نوعها.

---

## 1) أول ما تتصل

السيرفر بيبعتلك تلقائيًا رسالة `state` فيها الحالة الحالية كاملة، من غير ما تطلب حاجة:

```json
{
  "type": "state",
  "data": {
    "active_blocks": [
      {
        "ip": "192.168.10.55",
        "block_type": "permanent",
        "created_at": "2026-07-18T14:50:21.880459",
        "timeout": null,
        "expires_at": null,
        "active": true,
        "reason": "Port Scan",
        "source": "ResponseEngine"
      }
    ],
    "whitelist": ["192.168.10.150"],
    "stats": {
      "total_blocks": 2,
      "permanent_blocks": 1,
      "temporary_blocks": 1,
      "active_blocks": 1,
      "whitelist_size": 1,
      "total_actions": 3,
      "total_errors": 0,
      "uptime_seconds": 120
    }
  }
}
```

---

## 2) طلبات ترسلها للسيرفر (Requests)

كل طلب اختياري فيه `request_id` (أي string من عندك) — لو بعتيه، السيرفر هيرجّعه في الرد عشان تربطي الرد بالطلب.

### حظر IP دائم

```json
{ "type": "block", "ip": "192.168.10.55", "attack": "Port Scan", "severity": "High", "source": "Dashboard", "request_id": "req-1" }
```

### حظر IP مؤقت

```json
{ "type": "temp_block", "ip": "192.168.10.11", "timeout": 300, "attack": "Brute Force", "severity": "Medium", "source": "Dashboard", "request_id": "req-2" }
```

### فك حظر

```json
{ "type": "unblock", "ip": "192.168.10.55", "source": "Dashboard", "request_id": "req-3" }
```

### إضافة/إزالة من الـ Whitelist

```json
{ "type": "add_whitelist", "ip": "10.0.0.5", "request_id": "req-4" }
{ "type": "remove_whitelist", "ip": "10.0.0.5", "request_id": "req-5" }
```

### طلب الحالة الحالية يدويًا

```json
{ "type": "get_state", "request_id": "req-6" }
```

### طلب الـ History

```json
{ "type": "get_history", "request_id": "req-7" }
```

---

## 3) ردود السيرفر على الطلبات (Responses)

بترجع بنفس `request_id` اللي بعتيه:

```json
{
  "type": "result",
  "request_id": "req-1",
  "data": {
    "success": true,
    "action": "block",
    "ip": "192.168.10.55",
    "message": "IP blocked successfully.",
    "verified": true,
    "timestamp": "2026-07-18T14:50:21.881126",
    "details": {},
    "source": "Dashboard"
  }
}
```

لو `success: false`، اتفرجي على `message` عشان تعرفي السبب (IP غلط، محظور مسبقًا، في الـ whitelist، فشل اتصال بالراوتر... إلخ).

---

## 4) تحديثات لحظية (Events) — الجزء الأهم

**من غير ما تطلبي حاجة**، أي عملية حظر/فك حظر بتحصل — حتى لو حصلت تلقائيًا (تايمر الحظر المؤقت انتهى) — السيرفر بيبعتها لكل الداشبوردات المتصلة فورًا:

```json
{
  "type": "event",
  "data": {
    "success": true,
    "action": "unblock",
    "ip": "192.168.10.11",
    "message": "IP unblocked successfully.",
    "verified": true,
    "timestamp": "2026-07-18T14:50:53.541911",
    "details": {},
    "source": "Auto Timer"
  }
}
```

**مهم جدًا:** فرّقي بين الحدث اليدوي والتلقائي عن طريق حقل `source`:
- `"source": "Dashboard"` → حد عمل الفعل يدويًا من الداشبورد.
- `"source": "Auto Timer"` → التايمر الداخلي هو اللي فك الحظر المؤقت لوحده.
- `"source": "Suricata"` (أو أي مصدر تاني) → لو النظام اتوصل لاحقًا بنظام كشف تلقائي.

الداشبورد المفروض يستمع لرسائل `type: "event"` باستمرار ويحدّث الـ UI فورًا (يزوّد/يشيل من قائمة المحظورين) من غير ما يحتاج يعمل `get_state` كل شوية.

---

## 5) رسايل خطأ

```json
{ "type": "error", "request_id": "req-x", "message": "unknown action: xyz" }
```

---

## ملخص سريع للفريق

| الحقل | الوصف |
|---|---|
| `type` | نوع الرسالة: `state` / `result` / `event` / `error` / `history` |
| `request_id` | بيربط الطلب بالرد بتاعه (اختياري) |
| `data` | المحتوى الفعلي |

**Best practice للداشبورد:** خليكم بتستمعوا لرسائل `event` دايمًا (ده اللي هيخلي الشاشة تتحدث لوحدها لحظيًا)، واستخدموا `request_id` بس عشان تعرفوا رد أي زرار ضغطتوا عليه.
