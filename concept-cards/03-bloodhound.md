# Concept Card: BloodHound Attack-Path Recon

## الفكرة ببساطة
BloodHound أداة بتجمع كل العلاقات داخل الـ Active Directory (مين عضو في
مين، مين عنده صلاحية على مين، مين logged-in فين) وتبنيها كـ graph في
قاعدة بيانات Neo4j. بعدين تقدر تسأل سؤال بسيط زي:

> "إيه أقصر طريق من حساب `karim` لحد ما يوصل لـ `Domain Admins`؟"

وتاخد إجابة بصرية فورية بدل ما تدور يدويًا على كل الصلاحيات في الدومين.

## ليه الأداة دي خطيرة
لأنها بتحول هجوم معقد (privilege escalation عبر سلسلة صلاحيات متشابكة)
لمشكلة **shortest path** بسيطة. مهاجم بمستخدم عادي واحد يقدر يلاقي طريقه
لـ Domain Admin في ثواني، حتى لو الطريق ده معدي بخمس أو ست صلاحيات مختلفة
(GenericAll, WriteDacl, AllExtendedRights, MemberOf...).

## إزاي استخدمناها في اللاب
```
SharpHound (collection) -> رفع البيانات لـ Neo4j -> BloodHound GUI
MATCH p=shortestPath((n:User {name:"KARIM@CORP.LOCAL"})-[*1..]->(m:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})) RETURN p
```

النتيجة: BloodHound ورّى إن `karim` عنده `GenericAll`/`AllExtendedRights`
وصلاحيات DCSync مباشرة على الدومين object — وده بالظبط اللي خلانا نكتشف
الـ misconfiguration (راجع `05-dcsync.md`) **قبل** ما نستغلها، مش بعدها.

كمان اكتشفنا إن فيه مجموعة حسابات baseline (مش `karim`) متجهزة مسبقًا
بصلاحيات DCSync كجزء من واقعية اللاب: `CARMEN_CAMPBELL`, `WILBUR_LAWSON`,
`CHRISTA_LINDSEY`, `LOUISA_ALLISON`, `BEATRICE_FARMER`, `ADMINISTRATOR`,
`DC01$` — ده فرّق لنا إن صلاحيات `karim` كانت مشكلة منفصلة تستاهل تحقيق.

## ليه صعب نكتشفها بالـ logs
BloodHound/SharpHound بيجمع المعلومات عن طريق LDAP queries عادية (reads)
و SMB/WMI session enumeration — مفيش "BloodHound signature" واحدة واضحة في
الـ logs. أقرب إشارة ممكنة هي **حجم غير طبيعي** من LDAP reads من مصدر واحد
في فترة قصيرة (anomaly بالـ volume مش بالـ content). ده بيخليها recon صعبة
الاكتشاف جدًا مقارنة بالهجمات التانية في اللاب.

## التوصية الدفاعية
- تقليل مسارات الصلاحيات غير الضرورية (Tier-0 model, least privilege).
- مراقبة حجم LDAP queries غير العادي من حساب واحد (volume-based detection).
- مراجعة دورية بـ BloodHound نفسه من جانب الـ defenders (Purple Team) عشان
  يلاقوا نفس المسارات اللي المهاجم هيلاقيها قبل ما يستغلها.
