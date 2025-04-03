export default {
  authorize: {
    title: "تفويض التطبيق",
    description: "يطلب التطبيق الوصول إلى المعلومات التالية عنك:",
    new: "جديد",
    approve: "الموافقة",
    cancel: "إلغاء",
    missingClientId: "معرف العميل مفقود",
    missingRedirectUri: "عنوان URI لإعادة التوجيه مفقود",
    missingResponseType: "نوع الاستجابة مفقود",
    missingState: "معلمة الحالة مفقودة",
    invalidResponseType: "نوع الاستجابة غير صالح",
    missingParams: "المعلمات المطلوبة مفقودة",
    failed: "فشل التفويض",
    error: "خطأ في التفويض: {{error}}"
  },
  test: {
    failedVerifyIdToken: "فشل التحقق من رمز الهوية",
    clientSecret: "سر العميل",
    clientID: "معرف العميل",
    redirectURI: "عنوان URI لإعادة التوجيه",
    responseType: "نوع الاستجابة",
    scope: "النطاق",
    state: "الحالة",
    nonce: "Nonce",
    codeVerifier: "مدقق الرمز",
    codeChallenge: "تحدي الرمز",
    codeChallengeMethod: "طريقة تحدي الرمز",
    code: "رمز التفويض",
    token: "الرمز",
    status: "الحالة",
    auth: "المصادقة",
    userInfo: "معلومات المستخدم",
    idToken: "رمز الهوية",
    accessToken: "رمز الوصول",
    title: "صفحة اختبار OIDC",
    oidcConfig: {
      invalidURL: "عنوان URL غير صالح",
      authorizationEndpointRequired: "نقطة نهاية التفويض مطلوبة",
      tokenEndpointRequired: "نقطة نهاية الرمز مطلوبة",
      userinfoEndpointRequired: "نقطة نهاية معلومات المستخدم مطلوبة",
      title: "معلومات تكوين OIDC",
      authorizationEndpoint: "نقطة نهاية التفويض",
      tokenEndpoint: "نقطة نهاية الرمز",
      userinfoEndpoint: "نقطة نهاية معلومات المستخدم",
      jwksEndpoint: "نقطة نهاية JWKS",
      scope: "النطاق",
      issuer: "المصدر",
      scopeRequired: "النطاق مطلوب",
    },
    oidcStatus: {
      code: {
        title: "الحصول على رمز التفويض"
      },
      token: {
        idToken: "رمز الهوية",
        accessToken: "رمز الوصول",
        title: "الحصول على الرمز"
      },
      userInfo: {
        title: "الحصول على معلومات المستخدم"
      },
      refreshToken: {
        title: "تحديث الرمز"
      },
      idToken: {
        title: "الحصول على/التحقق من رمز الهوية"
      },
    },
  },
  callback: {
    processing: "تتم معالجة التفويض...",
    success: "نجح التفويض",
    failed: "فشل التفويض",
    noCode: "لم يتم استلام رمز تفويض",
    closeNow: "أغلق على الفور",
    closeIn: "{{timerInterval}} ثانية لإغلاق الصفحة",
    close: "أغلق على الفور"
  }
}; 