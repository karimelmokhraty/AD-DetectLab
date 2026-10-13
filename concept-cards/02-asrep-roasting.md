# Concept Card: AS-REP Roasting

## الفكرة ببساطة
في بروتوكول Kerberos العادي، أول خطوة (AS-REQ) المفروض الـ client يثبت هويته
الأول (pre-authentication) قبل ما الـ KDC يرد عليه. لو حساب معين عنده إعداد
`Do not require Kerberos preauthentication` (UF_DONT_REQUIRE_PREAUTH) مفعّل،
أي حد يقدر يطلب AS-REP باسم الحساب ده **من غير ما يعرف الباسورد خالص**.

الـ AS-REP اللي بيرجع بيكون جزء منه متشفر بمفتاح مشتق من باسورد الحساب
نفسه — فلو كرآتر الهجوم جابه، يقدر يحاول يفك التشفير offline (crack) باستخدام
hashcat، زي بالظبط اللي بيحصل في Kerberoasting، بس هنا مش محتاج SPN ولا
صلاحية أي حساب domain.

## الفرق عن Kerberoasting
| | Kerberoasting | AS-REP Roasting |
|---|---|---|
| الـ event | 4769 (TGS Request) | 4768 (AS-REQ/TGT) |
| محتاج حساب domain صالح؟ | أيوه (لازم تطلب الـ TGS) | **لأ** - أي حد يقدر يطلب AS-REQ |
| شرط الحساب | لازم يكون عنده SPN | لازم `DONT_REQ_PREAUTH` مفعّل |

## خطوات الهجوم
```bash
impacket-GetNPUsers corp.local/ -usersfile users.txt -outputfile asrep_hash.txt -dc-ip 192.168.154.10
hashcat -m 18200 asrep_hash.txt /usr/share/wordlists/rockyou.txt
```
النتيجة الفعلية: `svc-helpdesk : Welcome1`

## Detection Logic
الـ event المفتاحي: **4768** مع `Pre_Authentication_Type=0`.

```spl
index=ad_lab EventCode=4768 Pre_Authentication_Type=0
| stats count, values(Client_Address) as source_ip by Account_Name
```

**ميزة مهمة:** لأنه ممكن يستخدم كـ *enumeration* ضد أي حساب (مش بس اللي
فعلاً عنده الإعداد ده)، العدد الكبير من الـ hits بيدي صورة واضحة عن كل
الحسابات الـ vulnerable في الدومين دفعة واحدة — في اللاب لقينا 178 event
مطابق في مسح واحد.

## التوصية الدفاعية
- مراجعة دورية لأي حساب عليه `DONT_REQ_PREAUTH` ومعرفة سبب وجوده (عادة
  بيكون legacy compatibility احتياج حقيقي نادر).
- باسوردات قوية لأي حساب كهذا حتى لو الـ hash اتسرب، يصعب الكراك.
- alert فوري على أي spike في events 4768 بـ Pre_Auth_Type=0 من مصدر واحد.
