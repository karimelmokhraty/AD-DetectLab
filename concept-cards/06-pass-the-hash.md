# Concept Card: Pass-the-Hash (T1550.002)

## الفكرة ببساطة
بروتوكول NTLM بيتحقق من هويتك عن طريق إن جهازك يثبت إنه "عارف" الـ NTLM
hash بتاع الباسورد (عن طريق تشفير challenge بيه)، مش عن طريق إرسال
الباسورد نفسه. يعني لو حد سرق الـ hash بس (من غير ما يفك تشفيره
للباسورد الأصلي)، يقدر يستخدمه مباشرة في عملية الـ authentication —
بيمرر الـ hash (Pass-the-Hash) بدل ما يمرر الباسورد.

## الفرق عن Golden Ticket
| | Golden Ticket | Pass-the-Hash |
|---|---|---|
| البروتوكول | Kerberos | NTLM |
| المفتاح المستخدم | `krbtgt` hash | NTLM hash بتاع الحساب نفسه |
| بيأثر فيه تدوير `krbtgt`؟ | أيوه (بيبطّله) | **لأ** (مش له علاقة بـ krbtgt خالص) |

**ده درس مهم:** تدوير الـ `krbtgt` password (اللي عملناه كـ remediation
للـ Golden Ticket) **محصنش ضد PtH خالص** — لازم كل حساب يتغيّر الباسورد
بتاعه بشكل منفصل لو الـ NTLM hash بتاعه اتسرق.

## خطوات الهجوم
```bash
impacket-psexec -hashes <LM_hash>:<NTLM_hash> Administrator@192.168.154.10
```
دخلت كـ Administrator على DC01 من غير أي باسورد — بس بالـ NTLM hash اللي
جبناه من الـ DCSync الأول.

## Detection Logic
الحساب بيعمل logon بـ `Authentication_Package=NTLM` و`Logon_Type=3`
(network logon)، وده **غريب** في بيئة AD طبيعية لأن الافتراضي هو
Kerberos. أي حساب domain بيستخدم NTLM من غير سبب واضح (legacy app
مثلاً) يستاهل تحقيق.

**الميزة هنا (بعكس هجمات Kerberos اللي عملناها):** event الـ 4624 بيدي
الـ `Source_Network_Address` مباشرة — ربط الهجوم بمصدره أسهل بكتير من
الـ Kerberos events اللي احتجنا نلف عليها شوية عشان نلاقي IP.

**النتيجة اللي لقيناها فعليًا:**
```
Administrator | NTLM | Logon_Type=3 | Source=192.168.154.129 | Workstation_Name=(فاضي)
```

## التوصية الدفاعية
- تعطيل NTLM بالكامل في الـ domain لو ممكن (أو تقييده بـ Restrict NTLM
  GPO policies) والاعتماد على Kerberos بس.
- لو NTLM لازم يفضل شغال (توافق مع أنظمة قديمة)، راقب أي استخدام له
  لحسابات حساسة (Domain Admins) كـ alert عالي الأولوية.
- تدوير NTLM hash لأي حساب تم تسريبه (منفصل تمامًا عن تدوير `krbtgt`).
- Credential Guard على الأجهزة بيصعّب استخراج الـ hashes من الذاكرة من
  الأول (دفاع وقائي قبل ما الهجوم يحصل).
