OC.L10N.register(
    "ldap_write_support",
    {
    "Could not find related LDAP entry" : "تعذّر إيجاد مدخل LDAP المطلوب",
    "DisplayName change rejected" : "تمّ رفض تغيير الاسم المعروض DisplayName",
    "Write support for LDAP" : "دعم الكتابة إلى LDAP",
    "Adds support for creating, manipulating and deleting users and groups on LDAP via Nextcloud" : "إضافة دعم إنشاء، و جلب، و حذف المستخدمين و المجموعات من LDAP عبر نكست كلاود",
    "The write support for LDAP enriches the LDAP backend with capabilities to manage the directory from Nextcloud.\n* create, edit and delete users\n* create, modify memberships and delete groups\n* prevent fallback to the local database backend (optional)\n* auto generate a user ID (optional)\n* and more behavioral switches" : "يعمل دعم الكتابة لـ LDAP على إثراء واجهة LDAP الخلفية بإمكانيات إدارة الدليل من نكست كلاود مثل: \n* إنشاء وتحرير وحذف المستخدمين \n* إنشاء وتعديل العضويات وحذف المجموعات \n* منع الرجوع إلى الواجهة الخلفية لقاعدة البيانات المحلية (اختياري) \n* إنشاء مُعرِّف المستخدم ID تلقائيًا (اختياري) \n* والمزيد ...",
    "Writing" : "الكتابة",
    "Switches" : "تبديلات",
    "Prevent fallback to other backends when creating users or groups." : "منع الرجوع إلى الواجهات الخلفية الأخرى عند إنشاء مستخدمين أو مجموعات.",
    "To create users, the acting (sub)admin has to be provided by LDAP." : "لإنشاء مستخدمين، يجب توفير المشرف (أو المشرف الفرعي) بواسطة LDAP",
    "A random user ID has to be generated, i.e. not being provided by the (sub)admin." : "يجب إنشاء معرف مستخدم عشوائي، أي لا يتم توفيره بواسطة المشرف (أو المشرف الفرعي).",
    "An LDAP user must have an email address set." : "كل مستخدم في LDAP، يجب أن يكون له عنوان بريد إلكتروني.",
    "Allow users to set their avatar" : "السماح لكل مستخدم يتعيين آفاتار avatar خاص به",
    "User template" : "قالب المستخدِم",
    "LDIF template for creating users. Following placeholders may be used" : "قالب LDIF لإنشاء المستخدمين. يمكن استخدام العناصر النائبة placeholders التالية",
    "the user id provided by the (sub)admin" : "مُعرِّف المستخدم المُعطى من قِبَل المشرف (أو المشرف الفرعي).",
    "the password provided by the (sub)admin" : "كلمة المرور المعطاة من قِبَل المشرف (أو المشرف الفرعي)",
    "the LDAP node of the acting (sub)admin or the configured user base" : "خلية LDAP node الخاصة بالمشرف (أو المشرف الفرعي) أو قاعدة المستخدمين user base التي تم تكوينها",
    "Failed to set user template." : "تعذّر تعيين قالب المستخدِم",
    "Failed to set switch." : "تعذّر تعيين التبديلة switch.",
    "The write support for LDAP enriches the LDAP backend with capabilities to manage the directory from Nextcloud.\n* create, edit and delete users\n* create, modify memberships and delete groups\n* prevent fallback to the local database backend (optional)\n* auto generate a user id (optional)\n* and more behavioral switches" : "يعمل دعم الكتابة على LDAP على إثراء واجهة LDAP الخلفية بإمكانيات إدارة دليل LDAP من داخل نكست كلاود. \n* إنشاء و تحرير وحذف المستخدمين \n* إنشاء وتعديل العضويات وحذف المجموعات \n* منع الرجوع إلى الواجهة الخلفية لقاعدة البيانات المحلية (اختياري) \n* إنشاء معرف مستخدم تلقائيًا (اختياري) \n* والمزيد من التبديلات في التصرفات"
},
"nplurals=6; plural=n==0 ? 0 : n==1 ? 1 : n==2 ? 2 : n%100>=3 && n%100<=10 ? 3 : n%100>=11 && n%100<=99 ? 4 : 5;");
