ATUL MULTI-SHOP BILL MANAGER — SETUP GUIDE (Hindi)
=================================================

इसमें:
- Super Admin मोबाइल: 7248855446
- Registration पर विकल्प: Atul Jan Seva Kendra से जुड़ें / नई दुकान या CSC बनाएँ
- Atul workspace join request pending रहेगी; Super Admin approval के बाद ही access मिलेगा।
- नई दुकान बनाने वाला व्यक्ति उस workspace का Owner होगा।
- हर tenant/shop का data अलग tenant_id से सुरक्षित रखा जाता है।
- Owner अपनी दुकान के operators, services/rates और bills देखता है।
- Operator उसी workspace में केवल अपने बनाए bills देखता है।
- Super Admin सभी दुकानों की सूची, sales totals, bill counts, pending join requests, audit log और suspend/activate controls देख सकता है।
- दुकान का नाम, पता, phone और logo Owner सेट कर सकता है।
- Password PBKDF2 hashed है; session HttpOnly Secure cookie में है।

CLOUDFLARE SETUP
----------------
1. ZIP extract करें। GitHub पर पूरा folder upload करें (public, functions, schema.sql, wrangler.toml सब)।
2. Cloudflare Dashboard -> Workers & Pages -> Create -> Pages -> Connect to Git.
3. GitHub repo चुनें। Framework preset: None. Build command खाली रखें. Build output directory: public.
4. Deploy करने से पहले D1 बनाएँ: Workers & Pages -> D1 SQL Database -> Create database.
   Database name: atul-multishop-db
5. D1 Console में schema.sql का पूरा SQL paste करके Execute करें।
6. D1 database ID copy करें और wrangler.toml में PASTE_D1_DATABASE_ID_HERE की जगह डालें।
7. Pages project -> Settings -> Functions -> D1 database bindings:
   Variable name: DB
   Database: atul-multishop-db
   Save करें और redeploy करें।
8. Pages project -> Settings -> Variables and Secrets में Production और Preview (यदि उपयोग करें) के लिए:
   SUPER_ADMIN_PHONE = 7248855446
   ADMIN_SETUP_KEY = अपना मजबूत random secret (कम से कम 25 अक्षर)
   Save करें और redeploy करें।
9. साइट खोलें। पहली बार Super Admin setup box दिखेगा। मोबाइल 7248855446, अपना नया मजबूत password और ADMIN_SETUP_KEY डालें।
10. अगली बार Login tab से प्रवेश करें। ADMIN_SETUP_KEY किसी operator/shop owner को न दें।

IMPORTANT SECURITY / PRODUCT NOTES
----------------------------------
- यह starter application है। Live business use से पहले test accounts बनाकर tenant isolation, login/logout, backup और restore का परीक्षण करें।
- किसी operator को Atul Jan Seva Kendra में सीधे access नहीं मिलता; Super Admin approval जरूरी है।
- New shop owner अपनी दुकान का workspace और details manage कर सकता है। वह अपना Workspace Code operators को देगा; वे Registration में दूसरी दुकान से जुड़ने का विकल्प चुनकर request भेजेंगे। Owner approval workflow इस starter version में Super Admin approval तक सीमित है; operator membership approvals UI अभी शामिल नहीं है।
- Super Admin panel tenant list, totals, pending approvals, audit logs, reports, service rates और प्रति दुकान नवीनतम 500 bills का inspection देता है।
- गलत rate पर report: Owner report submit कर सकता है; audit log में service/rate changes record होते हैं। Super Admin reports को देख सकने वाला global report endpoint इस starter में अभी नहीं जोड़ा गया है।
- Logo upload currently stores image data in D1; keep logo small (450KB). For larger scale, Cloudflare R2 storage is recommended.
- Existing old LocalStorage bills are NOT automatically imported. Old site से JSON/CSV backup अलग रखें; migration/import tool इस ZIP में नहीं है।
- Database backup नियमित लें। Super Admin setup key और passwords किसी से साझा न करें।
- इस ZIP में production-grade rate abuse detection, SMS OTP, password reset, email verification, rate limiting और automated backups शामिल नहीं हैं। बड़े स्तर पर उपयोग से पहले इन्हें जोड़वाएँ।
