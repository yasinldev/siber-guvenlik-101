
# Siber Güvenlik 101

Bu proje, kendini siber güvenlik alanlarında ilerletmek isteyen kişiler için oluşturulmuştur. 

> Bu dosya temel bilgi düzeyi olan kişiler için hazırlanmıştır. 

# Ağ (Networking)

Networking, siber güvenlik için temel bir öneme sahiptir çünkü siber güvenlik, veri ve sistemleri koruma amacı güderken bu verilerin taşındığı veya erişilebildiği altyapıyı yani ağı, hedef alır. 

Kısacası networking siber güvenliğin yapı taşıdır dersek pekte yanılmayız. Ağı anlamadan etkin koruma önlemleri geliştirmek ve saldırıları tespit etmek veya farklı bir ağa saldırıda bulunmak pek mümkün değildir. Siber güvenlik uzmanları ve hackerlar çift taraflı bir bakış açısıyla ağ açıklarını anlamalı hem savunma mekanizmalarını kurabilmeli hemde saldırı için belirli ağ üzerinde istihbarat toplayabilme kapasitesine sahip olmalıdır. İşte bu yüzden networking kritik bir önem taşır.

## Ağ Yapısı

Öncelikle internetin ne olduğuna değinerek başlayalım. İnternet bütün dünyada kullanılan, bilgisayar ve diğer akıllı cihazlar aracılığı ile veri iletmeyi/almayı sağlayan temel iletişim ağıdır. 

İnternet içerisinde birden fazla protokol bulunur. Bunlar bir birine bağlı bilgisayar ağlarının bütünü olarak ta tanımlanabilir.

Kişisel cihazların birbirileri ile bağlantı kurabilmesi için genellikle bir telefon hattı veya radyo yayınları kullanılır. Telefon hatları bildiğimiz kablolar üzerinden kurulan bir iletişim ağı iken radyo yayınları Wİ-Fİ, uydu ve kablo ağları ile sağlanabilir. En yaygın olanı ise bir analog modem ile belli hızda bir internet servisinden yararlanmaktır. 

### WWW ve Web Sayfaları
World Wide Web (www), Hiper Metin İşaretleme Dili (HTML) kullanan, İnternet üzerindeki tüm kaynakların ve kullanıcıların birleşimidir. 

Bu dökümanların her birine web sayfası adı verilir ve web sayfalarında İnternet kullanıcısının bilgisayarında çalışan bir Web tarayıcısı adı verilen bir program sayesinde erişim elde edilir.

Her görüntülenen sitenin bir adresi numarası mevcuttur bu, dört yuvadan oluşan ve her yuvanın 0 ile 255 arası değeri olan bir adrestir. Fakat kullanıcı bu yalın sayı değerini her seferinde aklında tutamayacağından dolayı bu adresleri Web sayfasına eşdeğer tutan DNS bilgisayarları vardır.

![web](https://miro.medium.com/v2/resize:fit:1400/1*u7EwQyJGFcALPZ8noCvivQ.png)

DNS bilgisayarların görevi ise görüntülenecek her site ismine eş değer IP adresini hazır tutmak ve bilgi taşıma protokolünün paketlerini (TCP/IP) bu adrese yönlendirmektir. Tıpkı telefon rehberlerindeki isim-numara eşleştirmesi gibi alan adı-IP eşleştirmesi yapar. Böylece az uğraşla internet tarayıcısının çağırdığı sitedeki bilgilere ulaşılabilir.

### İnternet ve İntranet Arasındaki Farklar

İnternet dünya çapında milyonlarca bilgisayar ve ağın birbirine bağlandığı küresel bir ağdır. Web sayfaları, e-posta servisleri, sosyal medya platformları gibi pek çok hizmet internet üzerinden kullanıcılara sunulur.

Ancak İntranet'te bu ağ küresel değildir. İntranet belirli bir kuruluş, şirket veya organizasyon içerisinde barındırılan bir iç ağdır. Yalnızca yetkili kullanıcılar bu ağlarla bağlantı kurabilir ve genellike dışa kapalıdır. İntranet yalnızca İnternetin belirli özelliklerini kullanarak kurumsal iletişim, belge paylaşımı ve veri yönetimi gibi işlemleri sağlar.

![arasındaki fark](https://upload.wikimedia.org/wikipedia/commons/a/aa/Intranet.png)

Güvenlik bakımından İnternet küresel olduğu için güvenlik riskleri fazladır. Bahsi geçen ağ içerisindeki veriler, doğru güvenlik önemleri alınmazsa siber saldırılara, veri ihlallerine ve diğer tehditlere karşı savunmasız kalabilirler bunun yanı sıra İntranet üzerinde yalnızca yetkilendirilmiş kullanıcılar tarafından erişlebildiğinden dolayı İnternete göre daha güvenlidir. 

## OSI ve TCP/IP Modelleri
Açık Sistemler Ara Bağlantısı (OSI) modeli, ağ iletişimi işlevlerini yedi katmana bölen kavramsal bir çerçevedir. Çeşitli donanım ve yazılım teknolojilerinin coğrafi ve siyasi sınırlar arasında tutarlı bir şekilde çalışması gerektiğinden dolayı, ağ üzerinden veri göndermek genellikle daha karmaşık olarak kabul edilir. OSI veri modeli bilgisayar ağları arasında hem yazılım hemde donanımsal ağ iletişimi sağlar. Bu sayede iki bağımsız sistemin mevcut çalışma katmanın bağlı olarak, standartlaşmış arabirimler veya protokoller aracılığı ile iletişim kurması sağlanacak şekilde tasarlanmıştır.

OSI katmanlarının amacı herbir görevi bir üst katmana servis sağlamaktır. İki bilgisayar arasındaki iletişimde katmanlar sırasıyla iletişim kurar, eş düzeydeki katmanlar arasında doğrudan iletişim kurulmaz ancak aralarında sanal bir iletişim ağı oluşturulabilir. Aşağıdaki görselde her bir katmana ve katmanlara özgü saldırı yöntemlerine yer verilmiştir. Bu konuya tekrardan geleceğiz lakin öncelikle temel kavramları bitirmemiz gerekiyor.

![osi_model](https://www.stackscale.com/wp-content/uploads/2023/04/OSI-model-layers-attacks-Stackscale.jpg)

### OSI Katmanları

<b>7. Katman:</b> Uygulama katmanı, hem ana bilgisayar hem de kullanıcıya yönelik uygulamalarda iletişim kurmaktan sorumlu olan katmandır. Bu kullanıcıyla bire bir etkileşimin en fazla olduğu katymandır.

<b>6. Katman:</b> Sunu katmanı, verileri biçimlendirmekten ve uygulama katmanının belirttiği biçime çevirmekten sorumlu katmandır. Yani, uygulama katmanı tarafından gönderilen verilerin, alıcı sistemin uygulama katmanı tarafından okunabilir olmassını sağlamak için ağın veri çevirmeni olarak hareket eder.

<b>5. Katman:</b> Oturum katmanı, son kullanıcı uygulama süreçlerini yöneterek oturumları açma ve kapatmaktan sorumludur. Yerel ve uzak uygulamalar arasındaki bağlantıları kurar, yönetir ve sonlandırır.

<b>4. Katman:</b> Taşıma katmanı, değişken uzunluğundaki veri dizilerini kaynak ana bilgisayardan diğer hedef bilgisayara aktarmak için araçlar sağlamaktan sorumludur. Ağdaki noktalar arasında güvenilir bir iletim sasğlamak için bağlantı yönelimli ve bağlantısız olmak üzere iki modu tanır.

<b>3. Katman:</b> Ağ katmanı, paketlerin bir veya birkaç ağ üzerinden bağlı düğümler arasında aktarılması için araçlar sağlamaktan sorumludur. Trafiği yönetmek için routerlar ve switchler kullanılır.

<b>2. Katman:</b> Veri bağlantı katmanı, aynı yerel ağı içinde doğrudan bağlı iki düğüm arasında veri çerçevelerinin aktarılmasından sorumludur. Fiziksel katmandan ham bitleri çerçevelere paketler. Ayrıca hata denetimi ve düzeltmesi (debug handling) de gerçekleştirilebilir.

<b>1. Katman:</b> Fiziksel katman, cihazlar ve fiziksel iletim ortamları arasında yapılandırılmamış ham verilerin iletilmesinden ve alınmasından sorumludur. Çeşitli donanım teknolojileri aracılığyla uygulanabilir.

OSI modeline alternatif olarak geliştirilen TCP/IP modeli, pratik uygulamalarda daha yaygın olarak kullanılan bir ağ protokol modelidir. İnternet ve İntranetin temel protokollerini tanımlayan TCP/IP, dört katmandan oluşur ve bu katmanlar OSI modelindeki bazı katmanların işlevlerini birleştirir.

![tcp_ıp](https://cdn.hosting.com.tr/bilgi-bankasi/wp-content/uploads/2021/01/tcp_ip_katmanlari.jpg)

Protokol paketinin katmanları, alt kısımdaki katmanların veri transferine yakın olmasına rağmen, kullanıcı uygulamasına mantıksal olarak daha yakındır. 

Üst katman TCP (Transmission Control Protocol) verinin iletimden önce paketlere ayrılmasını ve karşı tarafta bu paketlerin yeniden düzgün bir şekilde bir araya getirilmesini sağlar. Alt katman IP (Internet Protocol) ise, iletilen paketin istenilen ağ adresine yönlendirilmesini kontrol eder.


### TCP/IP Katmanları

Katmanlara değinmeden önce TCP/IP protokol kümelerinden birazcık bahsetmek istiyorum çünkü ilerleyen süreçlerde sık sık TCP/IP modeli üzerinden işlem yapacağız.

TCP/IP protokol kümesi İnternet ve İntranet ağının oluşmasını sağlar bunu zaten biliyoruz. Bu protokol kümesi alt çekirdek protokol ve bir dizi yardımcı program (utility) içerir.

Altı çekirdek ve beş temel protokol şunlardır:

1. TCP (Transmission Control Protocol)
2. UDP (User Datagram Protocol)
3. IP (Internet Protocol)
4. ICMP (Internet Control Message Protocol)
5. IGMP (Internet Group Management Protocol)
6. ARP (Address Resolution Protocol)

Beş temel protokol ise şunlardır:

1. FTP (File Transfer Protocol)
2. TFTP (Trivial File Transfer Protocol)
3. HTTP (Hypertext Transfer Protocol)
4. HTTPS (Secure Hypertext Transfer Protocol)
5. SMTP (Simple Mail Transfer Protocol)

Yardımcı programlar ise, ağ iletişimi sırasında ağın düzgün çalışıp çalışmadığını kontrol etmek, sorunları teşhis etmek ve ağ ile ilgili bilgiler edinmek için kullanılır. 

Yaygın temel yardımcı uygulamalar şunlardır:

<b>Ping:</b> İnternet üzerinde varolan belirli bir IP adresinin ulaşılabilirliğini test eder. ICMP kullanarak hedefe "echo request" paketlerini gönderir ve "echo reply" almayı bekler. 

<b>Traceroute:</b> İnternet üzerindeki bir hedefe ulaşılana kadar geçtiği yönlendiricileri (routerları) takip ederek, her bir ara noktaya küçük TTL değerli paketleri gönderir ve yanıt süresini ölçer.

<b>FTP:</b> Bilgisayarlar ile TCP/IP hostları arasında tek yönlü dosya transferi sağlar. 

<b>Telnet:</b> Bir sunucu ile bağlantı kurarak belirli bir port üzerinden iletişim testi yapar. Bunun için genellikle uzak bir sunucuya terminal üzerinden bağlanarak, onunla manuel olarak iletişim kurulmasını sağlar.

<b>IPconfig\ifconfig:</b> Ağ arayüzü yapılandırma bilgilerini görüntüler ve yönetilmesini sağlar.

<b>ARP:</b> IP adreslerini fiziksel (MAC) adreslere çözümleyen ARP tablosunu görüntüler veya değiştirir.

Tekrardan katmanları yazmayacağım çünkü TCP/IP modeli, OSI katmanlarının 4'ünü temel alarak çalışır. Bu iki model arasındaki farkları daha iyi anlamak için aşağıda bir tablo eki bırakıyorum. Tablo, OSI ve TCP/IP modellerini karşılaştırmalı olarak incelemenize yardımcı olacaktır.

![osi_tcp_ip](https://media.geeksforgeeks.org/wp-content/uploads/20230417045622/OSI-vs-TCP-vs-Hybrid-2.webp)

## IP Adresleme, Subnetting ve CIDR (Classless Inter-Domain Routing)

IP adresleri ve Subnetting kavramları, bir network'ün doğru yapılandırılmasını sağlamak için kritik öneme sahiptir. Özellikle büyük ölçekli network'lerde, veri trafiğini yönetmek ve adresleme sisteminin optimizasyonunu sağlamak için bu iki kavramın derinlemesine bir şekilde anlaşılması gerekilir. 

Bir IP adresi, bir cihazın network üzerindeki kimliğini belirleyen sayısal bir adrestir. Bu adres, cihazların birbirileri ile iletişim kurmasını sağlar ve verilerin doğru kaynaktan doğru hedefe ulaşmasını güvence altına almayı hedefler. İki çeşit IP adresleme türü mevcuttur bunlar; IPv4 ve IPv6 adresleridir. 

IPv4 adresleri, 32-bitlik bir alan kullanır ve 4 (Octet) biçiminde yazılır. her bir Octet sekizlik bir nokta ile ayrılır ve her sekizlik, 0 ile 255 arasında bir değere sahiptir. Örneğin, 192.168.1.1 şeklinde bir IPv4 adresi, cihazın network üzerindeki benzersiz adresidir. Bu konudan yukarıda temel dahi olsa bahsetmiştik zaten. 

IPv6 adresleri ise, adres uzunluğunun 128-bit olmasının yanı sıra adresleme mimarisi ve adres yapısı bakımından IPv4 ile oldukça farklılık gösterir. Örneğin, aşağıda tipik iki IPv6 adresi verilmiştir. Göründüğü gibi her dört karakterden oluşan gruplar ":" işareti ile ayrılmıştır. 16'lık tabanda her bir karakteri 4-bit ile temsil edildiğinden dolayı dört karakteri toplamda 16-bit uzunluğundadır. ve birbirileri ile söylediğim gibi ":" karakteri ile ayrılır. Dolayısıyla bir IPv6 adresinde her biri 16-bitten oluşan 8 parça vardır.

a) 1234:5678:9ABC:DEF0:1234:5678:9ABC:DEF0

b) 1999:6:13:0:0:1962:2:15

![ipv6](https://upload.wikimedia.org/wikipedia/commons/thumb/7/70/Ipv6_address_leading_zeros.svg/1024px-Ipv6_address_leading_zeros.svg)

Network ID, adresin hangi network'e ait olduğunu tanımlarken, Host ID, network içerisindeki belirli bir cihazı temsil eder. Bu ayrımı yapmak için Subnet Mask kullanılır. Subnet Mask, IP adresinin hangi bitlerinin Network ID, hangilerinin Host ID olduğunu belirler. Örneğin, 255.255.255.0 Subnet Mask'ı, IP adresinin ilk 24 bitini yani üç Octet'ini Network ID olarak tanımlar ve geri kalan 8 bit Host ID olarak kalır.

### Subnetting 
Network yapısını alt ağlara bölme işlemine Subnetting denir bunu artık kavradığımızı düşünüyorum. Bu işlem ile IP uzayları alt sınıflara ayrılır. Ağın performansını arttırmak, IP adreslerini verimli bir şekilde kullanmak ve güvenliği güçlendirilmesi hedeflenir çünkü tek bir ağda bütün cihazların barındırılması, veri trafiğinin artması ve işlem karmaşıklığının artmasına yol açar. 

### CIDR (Classless Inter-Domain Routing)

Sınıflandırılmamış alanları arası yönlendirmede (CIDR), ağa ve kullanıcılara ayrılan bitleri ayırmak için kullanılır. CIDR, İnternet için yeni bir adresleme yönetimi olarak doğmuştur ve IP adreslerinin daha etkin kullanılmasını sağlar.

ISP'ler (Internet Service Provider), bireysel ya da kurumsal müşteriler için IP blokları tahsis eder. ISP'lerden bir IP bloğunu satın aldığınızda 192.168.24.32/16 benzeri bir ifade ile karşılaşırsınız. /16 değeri subnet maskınızda kaç adet 1 olacağını ifade eder. Yani sizin bloğunuzda 16 adet 1 olacağı belirtilmiş olur.

Bunu daha basit bir yöntemle anlatalım:

11111111.11111111.00000000.00000000 değeri aslında 255.255.0.0'a eşit hale gelir 16'lık 1 değerleri 8/8 olarak ayrılır ve her bir sekizlik 255 değerine tekabul eder.

# İşletim Sistemleri

İşletim sistemleri, siber güvenlik ve hacking alanlarında ilerlemek için aynı networking alanında olduğu gibi kritik öneme sahip alanlardan biridir. Bir bilgisayarın veya ağın tüm işleyişini yöneten yazılımlardır ve bu sistemler, her türlü siber saldırıya karşı savunmasız alanlar barındırır. Bir güvenlik uzmanı, hedef aldığı bir sistemde ne gibi zafiyetler olabileceğini ve bu zafiyetlerin nasıl istismar edilebileceğini anlaması için veya bir hackerin herhangi x kişi/kurum/kuruluşuna ait bir bilgisayara sızabilmesi için işletim sistemlerinin iç işleyişini bilmelidir.

İşletim istemlerinin temel bileşenlerinin nasıl çalıştığını anlamak, güvenlik açıklarını keşfetmek için ilk adımdır. Örneğin bir işletim sisteminin çekirdeği (kernel) bilgisayar donanımını doğrudan kontrol eder ve her türlü erişim, çekirdek tarafından denetlenir. Eğer çekirdekte bir güvenlik açığı varsa, bu açık istismar edilerek saldırganların sisteme tam erişim elde etmesini sağlar. 

Ayrıca, işletim sistemlerinde dosya yönetimi, bellek yönetimi ve kullanıcı yetkilendirme gibi temel güvenlik bileşenlerinin nasıl çalıştığını bilmek te oldukça önemlidir. Tekrardan bir örnek verecek olursak, dosya izinleri yalnızca belirli kullanıcıların belirli dosyaya erişmesini sağlar. Ancak, dosya izinlerinin yanlış bir şekilde konfigüre edilmesi hine saldırganların istismarına maruz kalabilir.

Bu ve bu tarz benzeri sebeplerden ötürü işletim sistemlerini anlamak oldukça önemlidir.

## İşletim Sistemlerinin Temelleri

İşletim sistemleri, yukarıda da bahsettiğimiz üzere bir bilgisayarın donanım kaynakarını yönten uygulama ve yazılımlarına hizmet sağlayan yazılımlarının bütünüdür. Bilgisayar donanımları ile uygulama yazılımları arasısnda bir köprü görevi görerek kullanıcıların sistemle etkileşim kurmasını sağlar. Örnek verecek olursak Microsoft Windows, macOS, GNU/Linux dağıtımları ve Android ile iOS yer alır.

İşletim sistemlerinin kullanım alanı yalnızca kişisel bilgisayarlar, cep telefonları ve web sunucularıyla sınırlı değildir. Dijital işlevlere sahip neredeyse tüm cihazlar, örneğin motorlu taşıtlar, beyaz eşyalar, akıllı saatler gibi kendi işletim sisstemlerine sahiptir.

Bahsi geçen sistemlerin, sahip oldukları genişliği ile değil donanım kaynaklarını verimli kullanma yetenekleriyle değerlendirilmelidir. Modern işletim sistemleri çoklu görev yönetimi, bellek yönetimi, dosya sistemleri ve kullanıcı arabirimi gibi kritik işlevleri yerine getirir ve cihazların performansını optimize eder.

### Tek / Çok Kullanıcılı İşletim Sistemleri
Tek kullanıcılı işletim sistemleri, herhangi bir zamanda yalnızca tek bir kullanıcıya sahip olacak bir bilgisayarda veya benzeri bir makinede kullanılmak üzere geliştirilmiş bir işletim sistemi türüdür. Bu işletim sistemi genellikle akıllı telefonlar ve iki yönlü mesajlaşma cihazlarında kullanılır.

![tek_os](https://images.javatpoint.com/operating-system/images/single-user-operating-system.png)

Çok kullanıcılı işletim sistemleri ise birden fazla sayıda kullanıcı aynı anda bir biligsayarın farklı kaynaklarına erişebilir bir biçimde ilgili bilgisayarı kullanabilir. Ana bilgisayar sistemine bağlı çeşitli kişisel bilgisayarlardan oluşan bir ağ sistemi kullanılır ve birden fazla kullanıcının aynı anda tek bir makineye erişmesine izin verir. Çeşitli bilgisayarlar ana bilgisayar sistemine bilgi gönderebilir veya alabilir. Böylece, ana bilgisayar sunucu olarak işlev görür ve diğer kişisel bilgisayarlar bu sunucunun istemcileri olarak çalışır.

![multi_os](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcTvfq0zJf-8Iy5aaR51lGEvvX7KtUA_L5DIgg&sg)

### Ağ Tabanlı İşletim Sistemleri

Ağ tabanlı işletim sistemleri (Network Operating System), bir sunucu üzerinde çalışan ve verileri, kullanıcıları, grupları, güvenliği, uygulamaları ve ağ üzerinde işlem gören diğer çoğu ağ işlevlerinin yönetilmesine olanak sağlayan bir işletim sistemi türüdür.

Ağ tabanlı sistemleri, bir ağ içerisinde bulunan bilgisayarların ağ içerisindeki diğer bilgisayarlarla yazıcı paylaşımı, ortak dosya sisteminin ve veritabanlarının paylaşımı gibi işlevleri yerine getirmek üzere tasarlanmıştır.

En popüler olanları Novell, NetWare, Linux, Windows Server dağıtımları ve Mac OS X'tir.

Ağ tabanlı işletim sistemileri, genellikle istemci/sunucu modelini kullanılır. Bu model ile çalışan işletim sistemlerinde işlevsellikler ve uygulamaları merkezileştirmek için özelleşmiş bir veya daha fazla sunucunun ağda bulunmasına olanak tanır. Bu sistemde, sunucu sistemin merkezidir ve güvenliği ile kaynaklarlara erişimi sağlar. 

![ag_os](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcRhvb-OtQRa9tkDzsRSHav-9UaMtzoO6t7TUA&s)

## İşletim Sistemi Çekirdekleri (Kernels)
İşletim sistemi çekirdeği, mevcut sistem üzerindedeki her şey üzerinde denetimi olan merkezi bir bileşendir. Uygulamalar ve donanım seviyesindeki bilgi işlemleri arasında köprü görevi görür. Çekirdeğin görevleri sistemin kaynaklarını yönetmeyi de kapsar. Genellikle çekirdek, işletim sisteminin temel bir elemanı olarak, yazılımın fonksiyonunun yerine getirebilmesi için kontrol etmesi gereken kaynaklar için düşük seviye soyutlama katmanı sağlayabilir.

### RAM (Random-Access Memory)
Rastgele erişim belleği (RAM), hem program talimatlarını hem de verileri geçiçi bir şekilde depolamak için kullanılır. Bir programın yürülebilmesi için her ikisinin de bellekte bulunması gerekir. Genellikle birden fazla program belleğe erişmek ister ve genellikle bilgisayarın sahip olduğundan daha fazla miktarlarda bellek erişimi talep edilir. Çekirdek, her işlemin hangi belleği kullanabileceğine karar vermekten ve yeterli bellek olmadığında ne yapılacağını bildirmekten sorumludur.

![ram](https://math.hws.edu/eck/cs124/javanotes6/c1/overview_fig1.gif)

### IO (Input/Output Devices)
I/O aygıları klavyeler, fareler, disk sürücüleri, yazıcılar, USB aygıtları, ağ bağdaştırıcıları ve görüntü aygıtları gibi çevre birimlerini içerir, ancak bunlarla sınırlı değildir. Çekirdek, uygulamaların uygulama ayrıntılarını bilmesine gerek kalmaması için tipik olarak çekirdek tarafından soyutlanan bu aygıtları kullanması için uygun yöntemler sağlar.

### Kaynak Yönetimi
Kaynak yönetimi, adres alanı ve korunma mekanizmalarını tanımlamayı içerir. Çekirdek, senkronizasyon ve işlemler arası iletişim (IPC) yöntemleri sunar. Bu işlemler çekirdek içinde olabilir veya diğer işlemlere güvenebilir. Çekirdek, IPC sağlayarak diğer olanaklara erişim sağlarken, çalışan programlar da bu olanaklara erişim için bir yöntem sunar. Ayrıca, çekirdek bağlam geçmişinden sorumludur.

### Bellek Yönetimi
Çekirdek, sistemin belleğine tam erişime sahiptir ve süreçlerin bu belleğe güvenli bir şekilde erişmesini sağlamalıdır. İlk adım genellikle sanal adresleme ile yapılır; bu, sayfalama ve/veya segmentasyon ile sağlanır. Sanal adresleme, çekirdeğin bir fiziksel adresi başka bir sanal adrese dönüştürmesini sağlar. Sanal adres alanları, farklı süreçler için farklı olabilir; böylece her program, sadece çekirdek dışında başka bir programın çalışmadığı gibi davranabilir.

Birçok sistemde, bir programın sanal adresi, bellekte mevcut olmayan verilere işaret edebilir. Sanal adresleme, işletim sisteminin verileri, ana bellekte tutmak yerine başka veri depolarında (örneğin sabit disk) tutmasını sağlar. Bu, işletim sistemlerinin programların fiziksel olarak mevcut olandan daha fazla bellek kullanmasına imkan tanır. Veriler RAM’de olmadığında, CPU çekirdeğe bir sinyal gönderir ve çekirdek, gerekli verileri RAM'e yükleyip programı devam ettirir. Bu yöntem "talep sayfalaması" olarak bilinir.

Sanal adresleme ayrıca belleği, bir kısmı çekirdek (çekirdek alanı) için, diğer kısmı ise uygulamalar (kullanıcı alanı) için ayrılmış iki bölüme ayırmaya olanak tanır. Uygulamalar, çekirdek belleğine erişemez, böylece uygulamalar çekirdeği zarar vermekten korunur. Bu bellek bölümü tasarımı, genel amaçlı çekirdeklerin çoğu için yaygın bir özellik olmuştur.

### Çekirdek Türleri

Çekirdek türleri, işletim sistemlerinin tasarımına göre farklılık gösterir ve genellikle üç ana kategoriye ayrılır.

#### Monolitik Çekirdekler
Monolotik çekirdekler, tüm sistem işlevlerini tek bir büyük yapı içinde barındırır. Donanım yönetimi, dosya sistemi, ağ yığını gibi tüm bileşenler tek bir çekirdek içinde bulunur. Bu yapı, hızlı ve verimli olmasına karşın, hataların tespiti ve çözülmesi daha zordur. Linux, eski Windows sürümleri gibi örnekler monolitik çekirdek kullanır.

#### Mikroçekirdekler (Microkernels)
Mikroçekirdekler, çekirdek işlevlerini daha küçük ve bağımsız birimler halinde ayırır. Bu tasarım, çekirdeğin temel işlevlerini (örneğin, bellek yönetimi, işlem zamanlaması) izole ederken, daha fazla işlevi kullanıcı alanındaki uygulamalara devreder. Bu tür çekirdekler daha esnek ve modülerdir, ancak performans açısından bazı ek yükler getirebilir. Örnek olarak, Minix gösterilebilir. Aşağıda Monolotik çekirdekler ile Mikroçekirdeklerin farkı gösterilmiştir.

![fark](https://upload.wikimedia.org/wikipedia/commons/thumb/6/67/OS-structure.svg/1200px-OS-structure.svg.png)

#### Hibrit Çekirdekler
Hibrit çekirdekler, monolitik çekirdek ve mikroçekirdek yaklaşımlarının birleşimidir. Bu çekirdekler, bazı çekirdek işlevlerini kullanıcı alanına kaydırırken, diğerlerini monolitik yapıda tutarak her iki dünyanın avantajlarını kullanmayı amaçlar. Windows NT, modern macOS ve bazı Linux dağıtımları hibrit çekirdek kullanır.

![hibrit](https://upload.wikimedia.org/wikipedia/commons/thumb/3/39/Kernel-hybrid.svg/300px-Kernel-hybrid.svg.png)

### Kabuk - Çekirdek Etkileşimleri
Kabuk, kullanıcı ile çekirdek arasındaki arayüzü sağlar ve işletim sisteminin işlevlerine erişimi kolaylaştırır. Kullanıcı, kabuk aracılığıyla komutlar girer ve bu komutlar sistem çağrıları aracılığıyla çekirdeğe iletilir. Kabuk, kullanıcıdan gelen dosya işlemleri, işlem başlatma veya bellek talepleri gibi istekleri çekirdeğe iletir, bu da çekirdeğin ilgili hizmetleri sağlamasını sağlar. Çekirdek, donanım yönetimi, bellek tahsisi ve işlem zamanlaması gibi düşük seviyeli işlevleri yerine getirirken, kabuk daha yüksek seviyede bir dil sunarak kullanıcı dostu bir arayüz sağlar. Ayrıca, kabuk ve çekirdek arasında sinyaller aracılığıyla iletişim kurulabilir; örneğin, bir işlem hata durumu ile karşılaştığında, çekirdek bu durumu sinyal ile kabuğa bildirir ve kabuk kullanıcıyı bilgilendirir. Bu etkileşim, kullanıcıların çekirdek fonksiyonlarına erişimini sağlarken, aynı zamanda çekirdeğin güvenliğini ve kararlılığını korur.

Örneğin Linux işletim sisteminde kabuk (Bash) ile çekirdek arasındaki etkileşimi ele alalım.

1. Kullanıcı, kabuk üzerinden `ls` komutunu girer. Bu komut, belirtilen dizindeki dosya ve klasörlerin listesini görmek için kullanılır.

2. Kabuk, kullanıcıdan aldığı `ls` komutunu bir sistem çağrısı olarak çekirdeğe iletir. Çekirdek, bu komutu işlemek için gerekli işlemi yapar ve ilgili dosya sistemine erişir.

3. Çekirdek, diske erişim sağlar ve belirtilen dizindeki dosya bilgilerini okur. Bu işlem, çekirdeğin dosya sistemi yönetimi kısmına aittir.

4. Çekirdek, işlemi tamamladıktan sonra, dosya listesini kabuğa geri gönderir. Kabuk, bu veriyi alır ve kullanıcıya terminalde listeler olarak gösterir.

### Sistem Çağrıları (System Call)
Sistem çağrıları (syscall), bir bilgisayar programının çalıştığı işletim sisteminden hizmet talep etmesini sağlayan temel bir mekanizmadır. Donanımla ilgili işlemler, yeni süreçlerin oluşturulması ve çalıştırılması veya işlem zamanlama gibi çekirdek hizmetlerine erişim sağlama gibi görevlerde kullanılır. Sistem çağrıları, bir süreç ile işletim sistemi arasında önemli bir iletişim arayüzü oluşturur. Çoğu işletim sisteminde, sistem çağrıları yalnızca kullanıcı alanından yapılabilirken, OS/360 gibi bazı sistemlerde ayrıcalıklı sistem kodu da bu çağrıları gerçekleştirebilir. Gömülü sistemlerde ise sistem çağrıları genellikle işlemcinin yetki modunu değiştirmez.

# Siber Güvenliğe Giriş

Networking ve işletim sistemlerinin temel konseptlerini öğrendik. Bu iki alan, siber güvenlik dünyasının yapı taşıdır desek yanılmayız (defalarca kere söyledim ancak bu konuda oldukça ciddiyim). Ağlar, bilgiyi bir noktadan diğerine taşırken işletim sistemleri, bu bilgiyi işleyen cihazların beynidir. Bu yapı taşlarını anlamak, bir bina inşa etmek için temeli doğru atmaya benzer: sağlam bir temel olmadan başarıya ulaşmak mümkün değildir.

Ancak, siber güvenlik bu iki alanla sınırlı değildir. Eğitimin bu kısmında edindiğimiz temel bilgilerin üzerine inşa ederek güvenlik stratejilerini, tehditleri ve korunma yöntemlerini öğrenmemiz gerekiyor. 

Bir sonraki konuya geçmeden önce bu eğitim bittikten sonra sağlam bir temelinizin oturacağı inancındayım ve sizinle beraber bende öğreniyorum ancak bunu yalnızca bu eğitim dökümanı değil bireysel azminiz ve bağlamlar arasındaki sabrınızında bir etkisi olacaktır. Bu sebepten ötürü kendinize olan inancınızı kaybetmemeniz oldukça önemli

### Yasal Uyarı
Siber güvenlik alanı yalnızca bir teknik bilgi yığını değil, aynı zamanda büyük bir sorumluluktur. Bir bilgisayar sitemine veya bir ağa erişim sağlamak yalnızca bilgi edinmek ya da bir sorunu çözmek amacıyla yapılmalıdır. Bu döküman veya farklı bir kaynaktan öğrendiğiniz her bilgi, etik sınırlar içinde kullanılmalı ve başkalarına zarar verme amacı taşımamalıdır. Siber güvenliğin temel prensiplerinden biri, "önce zarar verme" anlayışıdır. Etik değerler çerçevesinde hareket etmek, yalnızca kendi vicdanımızı rahatlatmakla kalmaz, aynı zamanda bu alandaki profesiyonelliğimizi ve itibarımızı güçlendirir.

Unutmayın ki hedefimiz, bu bilgi yığınını işleyip insanlık adına kullanılabilir bir hale getirmektir. Bu nedenle, etik hacking prensiplerine ve yasalara saygı göstermek, siber güvenlikte bir profesiyonelin en önemli özelliği olmalıdır.

## Siber Güvenliğin Temelleri
Siber güvenlik, elektronik ortamlarda verilerin, sistemlerin ve ağların saklanması, iletilmesi ve işlenmesi sırasında yetkisiz erişime, bozulmalara, hırsızlıklara veya kesintilere karşı korunmasını ve güvenli bir dijital ortam oluşturmayı amaçlayan bir disiplindir. Bu alan, üç temel ilkeye dayanır: gizlilik, bütünlük ve erişilebilirlik. Gizlilik, bilgilerin yalnızca yetkili kişiler veya sistemler tarafından erişilebilir olmasını sağlayarak veri sızıntılarının önüne geçmeyi amaçlar. Bütünlük, verilerin yetkisiz bir şekilde değiştirilmesini ya da bozulmasını engelleyerek doğruluğunu korur. Erişilebilirlik ise yetkili kullanıcıların ihtiyaç duyduğu bilgilere zamanında ve kesintisiz bir şekilde erişilebilmesini garanti eder. Bu saydığım ilkeler, siber güvenliğin temel taşlarını oluşturur ve bireysel/kurumsal/ulusal düzeyde dijital varlıkların korunmasını sağlar.

### Siber Güvenliğin Tarihi ve Önemi
Siber güvenliğin biraz tarihinden bahsetmek istiyorum, bilgisayarların ve internetin yaygınlaşmaya başladığı dönemlere gitmemiz gerekiyor bunun için. 1960'lar ve 1970'lerde, bilgisayarlar ilk kez ticari amaçlarla kullanmaya başlandı. O dönemde siber güvenlik, daha çok fiziksel güvenlik ile sınırlıydı çünkü çoğu sistem, ayrı ve izole ağlarda çalışıyordu. Ancak, bilgisayar ağları gelişmeye başladıktan sonra dijital tehditler de yavaş yavaş kendini göstermeye başladı.

1980'lerde, internetin ilk hali olan ARPANET'in kullanıma sunulmasıyla birlikte, siber güvenlik ihtiyacı artmaya başladı. Bu dönemde, ilk siber saldırılar ve virüsler görüldü. 1986'da, ilk "hacker" gruplarının ve virüslerin ortaya çıkmasıyla birlikte, siber güvenlik dünyasında önemli bir dönüm noktası yaşandı. Özellikle 1988'deki Morris Worm, internetin hızla büyüyen ağlarına ilk darbeyi vurdu. Bu olay ilk büyük siber saldırılardan biriydi ve siber güvenlik alanının önemini tüm dünyaya gösterdi.

1990'ların ortalarına gelindiğinde, ticaretin ve internetin hızla büyümesiyle birlikte siber güvenlik daha kritik bir alan haline geldi. Özellikle, e-ticaretin ve çevrimiçi bankacılığın yaygınlaşmasıyla birlikte, kişisel verilerin korunması ve dijital dolandırıcılık gibi tehditler gündeme gelmmeye başladı. Bu dönemde, antivirüs yazılımları ve güvenlik duvarları gibi ilk koruma araçları gelişmeye başladı.

2000'lerin başında, siber güvenlik alanı ciddi bir evrimsel sürece girdi. Devletler, şirketler ve bireyler dijital saldırılara karşı daha sofistike savunma yöntemleri geliştirmeye başladılar. Siber güvenlik, yalnızca bireysel bilgisayarların kullanıcıları için değil, aynı zamanda kritik altyapılara sahip devletler ve büyük şirketler için de temel bir öncelik haline geldi. Aynı zamanda, siber suçların artması ve daha karmaşık hale gelmesiyle, siber güvenlik uzmanlarına olan talep de önemli ölçüde arttı.

Son yıllara gelindiğinde, siber güvenlik tehditleri daha da çeşitlendi ve karmaşık hale geldi. Kötü niyetli yazılımlar (malware), fidye yazılımları (ransomware) ve devlet destekli siber saldırılar gibi tehditler, hem kurumsal hemde bireysel düzeyde ciddi güvenlik riskleri oluşturdu. Bu nedenle, siber güvenlik yalnızca teknolojik bir ihtiyaç değil, aynı zamanda toplumsal, ekonomik ve ulusal güvenlik açısından kritik bir alan haline geldi. Teknolojiye olan bağımlılığın arttığı günümüzde, siber güvenlik sürekli olarak evrilen bir alan olup, bireylerin ve kurumların dijital dünyada güvenliğini sağlamaya yönelik çözümler üretmeyi amaçlamaktadır.

### Siber Güvenlik Etiği ve Bireysel Sorumluluklar

Bu alan, yalnızca teknik beceriler ve araçlarla sınırlı olmayan, aynı zamanda yüksek etik standatlar ve sorumluluklar gerektiren bir alandır. Etik ve bireysel sorumlulukların yerine getirilmesi, siber güvenlik alanında profesiyonelleşmek isteyen bireylerin ve toplumların, dijital dünyadaki güvenliği sağlama amacı gütmeleri oldukça önemlidir zira bireysel ve toplumsal ölçeklerde zararlar verebilir ve yasaları ihlal ederek gelişmeye devam eden bir toplumun ayağına bir bağ olabilir.

#### Etik Hacking (Beyaz Şapkalılar)
Sİber güvenlik uzmanları ve etik hackerlar, kötü niyetli saldırganlardan farklı olarak, güvenlik açıklarını kötüye kullanmak yerine bu açıkları tespit eder ve ilgili birey/kuruluşlara bildirir. Etik hackerlar, sistemleri test ederken yalnızca izinli ve belirlenen sınırlar içinde hareket ederler. Bu tür hackerlar, aynı zamanda beyaz şapkalı hackerlar olarak da adlandırılır ve onların faaliyetleri, dijital ssistemlerin daha güvenli hale gelmesine katkı sağlar.

#### Gri Şapkalı Hackerlar
Gri şapkalı hackerlar, etik hackerlar ile siyah şapkalı hackerlar arasında bir yerde durur. Bu grup, genellikle sisteme izinsiz erişim sağlamakla birlikte, amacının kötüye kullanım olmadığını savunur. Gri şapkalı hackerlar, bir güvenlik açığını keşfettiğinde, bunu kötüye kullanmak yerine kuruluşlara bildirebilirler, ancak bunu yapmadan önce sisteme izinsiz girerek "test" yapabilirler. Ancak, bu tür faaliyetler yasadışıdır, çünkü hackerlar genellikle izin almadan sistemlere erişirler.

Gri şapkalı hackerların temel farkı, etik kurallara sadık kalmayıp bazen yasal sınırları ihlal etmeleridir. Amacın zarar vermek veya kişisel kazanç sağlamak olmadığını iddia etseler de, eylemleri yine de yasadışıdır. Gri şapkalı hackerlar bazen, güvenlik açığını ve zafiyeti erken keşfederek kurumu uyarma amacını güderken, aynı zamanda yasal olmayan bir şekilde bu süreci başlatmış olurlar.

#### Siyah Şapkalı Hackerlar (Kötü Niyetli Hackerlar)
Siyah şapkalı hackerlar, kötü niyetli hackerlardır ve yasa dışı faaliyetlerde bulunurlar. Bu hackerlar, sistemlere izinsiz erişim sağlamak, verileri çalmak, şifreleri kırmak veya bir sistemin kontrolünü ele geçirmek amacıyla hareket ederler. Siyah şapkalı hackerlar, zarar verme, kişisel kazanç sağlama (örneğin, fidye yazılımı kullanarak) veya sadece eğlence için saldırılar yapabilirler. Kötü niyetli yazılımlar, virüsler, trojanlar ve ransomware (fidye yazılımları) gibi zararlı yazılımları yayarak, sistemlere ciddi zararlar verirler.

Siyah şapkalı hackerlar, hedef aldıkları sistemlerin güvenliğini ihlal etmek ve genellikle sistemdeki verileri çalmak veya manipüle etmek amacıyla kötü niyetle hareket ederler. Bu grup, siber suç işleyerek suçluluklarının peşinden gitme riskine girerler ve birçok ülkede yasalar tarafından cezalandırılırlar.
