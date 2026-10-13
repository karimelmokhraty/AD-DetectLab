# Concept Card: DCSync (T1003.006)

## الفكرة ببساطة
الـ Domain Controllers بتتزامن (replicate) مع بعضها طول الوقت عن طريق بروتوكول
اسمه **MS-DRSR**، وده بيسمح لـ DC إنه يطلب من DC تاني "ابعتلي كل التغييرات
اللي حصلت، بما فيها كل الـ password hashes". المفروض الصلاحية دي تكون
لـ Domain Controllers بس.

**DCSync** هو لما حساب عادي (مش DC) عنده صلاحيتين معيّنتين:
- `DS-Replication-Get-Changes`
- `DS-Replication-Get-Changes-All`

فيقدر "يتنكر" إنه DC ويطلب نفس البيانات دي — يعني يسحب **كل** الـ
credentials في الـ domain (بما فيهم `krbtgt`) من غير ما يلمس أي ملف على
الـ DC، ومن غير ما يحتاج RDP أو shell access على الـ DC خالص.

## ليه ده خطير بالذات
- مش محتاج وجود فعلي (login) على الـ DC — بيحصل عن بعد بالكامل.
- مش بيلمس LSASS ولا NTDS.dit على القرص، يعني EDR/Antivirus اللي بيراقب
  "process accessing lsass.exe" أو "file read on ntds.dit" مش هيمسكه.
- بيديك مفتاح كل حاجة تانية: `krbtgt` hash → Golden Ticket، وأي حساب
  تاني (Domain Admin مثلاً) → استخدامه مباشرة (Pass-the-Hash).

## إزاي حصل في اللاب
`karim` كان عنده الصلاحيتين دول ممنوحين على الـ domain object (نتيجة
misconfiguration في الـ ACLs — زي اللي بيحصل غالبًا من BadBlood أو
misconfig حقيقي في بيئات الشركات). استخدمتهم بالأمر:
```bash
impacket-secretsdump -just-dc corp.local/karim:'Passw0rd!'@192.168.154.10
```
وده جاب كل حسابات الـ domain وهاشاتهم دفعة واحدة، بما فيهم `krbtgt`
(اللي استخدمناه بعد كده في الـ Golden Ticket).

## Detection Logic
الـ Event المفتاحي هو **4662** (Object Access) على الـ domain NC head،
لما يحتوي على الـ GUIDs بتاعة الـ replication rights:
- `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`
- `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`

**شرط مهم:** الـ event ده مش بيتسجل تلقائيًا. محتاج:
1. Object Access auditing مفعّل (DS Access subcategory)
2. SACL على الـ domain object نفسه (`DC=corp,DC=local`) بيراقب "Everyone"
   أو "Authenticated Users" على الـ extended rights دي تحديدًا.

ده نقطة مهمة جدًا تتقال في الـ interview: **معظم الشركات معندهاش الـ
SACL ده مفعّل من الأول**، فـ DCSync بيعدي من غير أي أثر خالص لو محدش
جهّز الـ auditing مسبقًا. ده فرق جوهري عن باقي الهجمات اللي عملناها
(زي Kerberoasting) اللي بتسجل events افتراضيًا من غير إعداد إضافي.

## ربط الهجوم بمرتكبه (Attribution)
الـ Account_Name في event الـ 4662 بيورّيك مين طلب الـ replication
(`karim`). ولو قارنت الـ `Client_Address` بتاعه مع الـ `Client_Address`
بتاع الـ 4769 events اللي جت بعد كده (باستخدام Golden Ticket باسم
`Administrator`)، هتلاقي **نفس الـ IP** — وده بيربط كل مراحل الهجوم
(DCSync → Golden Ticket → استخدامه) كـ kill chain واحد بغض النظر عن
اختلاف اسم الحساب المستخدم في كل مرحلة.

## التوصية الدفاعية
- **الأهم:** مراجعة دورية لحسابات الـ Domain Admins و"مين عنده صلاحية
  Replicating Directory Changes" — الصلاحية دي المفروض تكون محصورة في
  DCs وحسابات backup معدودة ومعروفة بس.
- تفعيل auditing على الـ domain object عشان event 4662 يتسجل أصلاً.
- تنبيه فوري (alert) على أي 4662 بالـ GUIDs دي من حساب مش computer account.

## Finding: Visibility Gap في منح الصلاحية نفسها
أثناء التحقيق، حاولنا نلاقي **إمتى ومين منح `karim` صلاحية الـ
Replication من الأول** (مش بس إمتى استخدمها). الـ log المفروض يسجل ده
هو **Event ID 5136** ("A directory service object was modified")، تحت
subcategory منفصل اسمه **"Audit Directory Service Changes"**.

**النتيجة:** `index=ad_lab EventCode=5136` رجع **0 results** — الـ
subcategory ده مش مفعّل في اللاب (ولا في معظم بيئات الشركات افتراضيًا،
لأنه تقيل على الأداء).

**ليه ده مهم:** فيه فرق جوهري بين نوعين من الـ auditing:
| النوع | بيسجل إيه | Event ID |
|---|---|---|
| Directory Service **Access** | حد *استخدم* صلاحية | 4662 |
| Directory Service **Changes** | حد *غيّر* الصلاحيات/الـ attributes | 5136 |

عندنا رؤية على النوع الأول بس. يعني لو ده كان incident حقيقي، كنا هنعرف
"مين استخدم DCSync" بس مش هنعرف "مين منح الصلاحية دي من الأول ولا
إمتى" — الـ root cause (الـ misconfiguration نفسها) كان هيفضل عمره ما
كان مراقب. ده finding بنفس أهمية اكتشاف الهجوم نفسه، وتوصية عملية
لأي SOC: تفعيل **الاتنين** مع بعض، مش بس واحد.
