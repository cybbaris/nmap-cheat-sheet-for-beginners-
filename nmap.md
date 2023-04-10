# NMAP, komut ve parametreleri 
(nmap cheat sheet: kopya kağıdı)

**NMAP SCRIPTLERİNİ GÜNCEL KULLAN: `nmap —script-updatedb`**

Nmap, ağdaki cihazlar için tarama, tespit ve keşif yapabilen gelişmiş ve ünlü bir programdır. 1997 yılından beri kullanılmaktadır. c/c++, python, lua programlama dilleriyle yazılmıştır.

Örnek kullanımı:

| Komut | Parametre | Argümanlar | Argümanlar** |
| --- | --- | --- | --- |
| nmap | -p(port) | 80 | 192.168.1.1 |
| nmap | -T(zaman) | 4 | 192.168.1.1-50 |
| nmap | -O
(işletim sistemi) |  | 192.168.1.0/24 |

Parametreler kombine edilerek kullanılabilir. Örn;

`nmap -p80,443,445(portlar) -sV(cihazda kullanılan servisler) -O(işletim sistemleri) —osscan-guess(agresifçe) 192.168.1.10-50 -T4(4/6 zaman aralığı)`

- **Anlamı:** “192.168.1.10 ila 50 IP aralığındaki cihazların 80, 443 ve 445 numaralı portlarını, 4/6 hızda tara, portlarda kullanılan servisleri ver ve cihazlardaki işletim sistemlerini agresifçe tespit et.”

| Hedef Tarama |  |
| --- | --- |
| nmap 192.168.1.15 | Tek IP Taraması |
| nmap 192.168.1.15 192.168.1.52 | Belirli IP’ler taraması |
| nmap 192.168.1.1-254 | IP aralığı taraması |
| nmap 192.168.1.0/24 | Ağ taraması |
| nmap abc.com | Domain (hostname) taraması |
| nmap -iL hedefler.txt | Dosyadaki hedeflerin toplu taraması |
| nmap -iR 100 | Belirli sayıda rastgele host araması |
| nmap —exclude 192.168.1.25 | Dışlanmış IP ile tarama |
| nmap 192.168.1.0/24 -n  | DNS çözümlemesiz tarama |
| nmap 192.168.1.0/24 -sn | Port taramasız ve isim çözümlemesiz. |
| nmap 192.168.1.0/24 -PR | ARP paketli ping taraması |
| nmap 192.168.1.0/24 -PN | Pingsiz, sadece port taraması |
| nmap 192.168.1.0/24 -PA | TCP ACK flag ile ping taraması |
| nmap 192.168.1.10 -sT | TCP port taraması |
| nmap 192.168.1.10 -sS  | SYN flag ile TCP port taraması |
| nmap 192.168.1.10 -sA  | ACK flag ile TCP port taraması |
| nmap 192.168.1.10 -sU  | UDP port taraması |
| nmap 192.168.1.10 —p 21-100  | Belirli port aralığının taranması |
| nmap 192.168.1.10 -p U:53,T:21-25,80 | Belirli UDP ve TCP portların taraması |
| nmap 192.168.1.10 —p-  | Tüm portların taranması |
| nmap 192.168.1.10 —p http,ftp | Servis adıyla port taraması |
| nmap 192.168.1.10 —F | Hızlıca 100 portun taranması |
| nmap 192.168.1.10 —top-ports 1000 | En bilinen 1000 portun taranması |

## **Servis ve Versiyon Tarama**

| nmap 192.168.1.10 -sV | Portta çalışan servisin versiyon taraması |
| --- | --- |
| nmap 192.168.1.10 -sV --version-instensity 8 | 0-9 arasındaki 8. hassasiyette versiyon taraması. 
 Yüksek sayı = doğru sonuç |
| nmap 192.168.1.10 -sV --version-light | Hafif ve hızlı versiyon taraması. |
| nmap 192.168.1.10 -sV --version-all | En yüksek (9.) seviyede versiyon taraması.. |

## **OS Tespiti Taraması**

| nmap 192.168.1.1 -O | OS taraması. 
→ TCP/IP fingerprint ile |
| --- | --- |
| nmap 192.168.1.1 -O —osscan-limit | TCP portu bulunan hedefler için tarama |
| nmap 192.168.1.1 -O —osscan-guess | Daha agresif tahminler ile tarama |
| nmap 192.168.1.1 -O —max-os-tries 1 | Bir kez denemeli OS taraması |
| nmap 192.168.1.1 -A | OS, versiyon ve güvenlik açığı taraması. |

## **Zaman ve Performans Ayarlı Tarama**

| nmap 192.168.1.1 -T0 | (Paranoid) IDS atlatmalı ve en yavaş tarama. 
→ Dış (WAN) ağda kullanım |
| --- | --- |
| nmap 192.168.1.1 -T1 | (Sneaky) IDs atlatmalı ve yavaş tarama. |
| nmap 192.168.1.1 -T2 | (Polite) Daha hızlı ama daha az tespitli tarama |
| nmap 192.168.1.1 -T3 | (Normal) Varsayılan hızda tarama |
| nmap 192.168.1.1 -T4 | (Aggresive) Hızlı ve agresif tarama.
→ Lokal (LAN) ağda kullanım. |
| nmap 192.168.1.1 -T5 | (Insane) En hızlı tarama.
→ Lokal (LAN) ağda kullanım. |

## **NSE (Nmap Script Engine) ile Tarama**

| nmap 192.168.1.1 -sC | En bilinen script’ler ile tarama |
| --- | --- |
| nmap 192.168.1.1 —script http-sql-injection | Belirli bir script ile tarama |
| nmap 192.168.1.1 —script smb* | Belirli scriptlerin tümüyle tarama |
| nmap —script snmp-sysdescr —script-args snmpcommunity=admin 192.168.1.1 | Argümanlı script taraması |
| nmap 192.168.1.1 —script vuln | Tüm scriptler ile tarama |
| nmap —script-updatedb | Script veri tabanının güncellenmesi.
→ Scriptler “/usr/share/nmap/scripts/” altındadır. |

## **Firewall ve IDS (Intrusion Detection System) Atlatmalı Tarama**

| nmap 192.168.1.1 -f | Parçalı IP paketleri ile tarama |
| --- | --- |
| nmap 192.168.1.1 —mtu 16 | Paket boyutunu değiştirerek tarama |
| nmap -D RND:10  | Rastgele 10 adet decoy(sahte) IP ile tarama |
| nmap -D 192.168.1.5,192.168.1.6,192.168.1.7 192.168.1.1 | Belirli sahte (decoy) ve çoklu IP’ler ile tarama. 
→ İçlerinde biz de olmalıyız. (192.168.1.7) |
| nmap -S http://www.microsoft.com http://wwww.facebook.com  | Belirli sahte bir kaynak ile hedef tarama. |
| nmap -g 53 192.168.1.1 | Belirli kaynak port numarasından tarama |
| nmap —proxies http://192.168.1.1.50:8080  http://192.168.1.1.20:80 192.168.1.1  | Belirli proxy’ler üzerinden tarama. |
| nmap —data-length 25 192.168.1.1 | Gönderilen paketler rastgele olarak 25 byte daha veri eklemeli tarama. |

## **Çıktı Alımlı Tarama**

| nmap 192.168.1.1 -oN abc.txt | Normal dosya çıktısı |
| --- | --- |
| nmap 192.168.1.1 -oX abc.xml | XML dosya çıktısı |
| nmap 192.168.1.1 -oG abc.grep | Grep dosya çıktısı |
| nmap 192.168.1.1 -oA sonuçlar | Üçlü formatta çıktı alımı |
| nmap 192.168.1.1 -v | Daha fazla detaylı tarama.
-v adedi arttırıldıkça detay alımı güçlenir. |
| nmap 192.168.1.1 -d  | Sadece açık portları görüntüleme |
| nmap 192.168.1.1 —open | sadece açık portları görüntüleme. |
| nmap 192.168.1.1 —packet-trace | Gönderilen ve alınan tüm paketleri görüntüleme  |
| nmap 192.168.1.1 —iflist | Hedefin ethernet ve route’larını görüntüleme |
| nmap —resume sonuç.txt | Dosyadan tarama devam ettirme. |

## **Kullanışlı örnekler ve yorumlama**

- `nmap -Pn —script=http-sitemap-generator abc.com`
    - [abc.com](http://abc.com) üzerinde pingsiz port taraması istiyorum ve http haritasının script komutu ile çağrılmasını söylüyorum.
- `nmap -n -Pn -p 80 —open -sV -vvv —-script banner,http-title -iR 1000`
    - dns çözümleme yapma, sadece port taraması yap (pingsiz) port 80’in arkasında çalışan bir uygulama varsa onun versiyonunu da bana göster. 3 kat fazla detay ver (verbose) script olarak banner,http-title scriptlerini kullan; random bir şekilde 1000 tane sunucu üzerinde bunu gerçekleştir.
- `nmap -Pn —script=dns-brute abc.com`
    - pingsiz sadece port taraması yap, dns brute komutunu(script) kullan. [abc.com](http://abc.com) üzerinde gerçekleştir.
- `nmap -n -Pn -vv -O -sV —script smb-enum*,smb-ls,smb-os-discovery,smb-s* 192.168.1.1`
    - dns çözümlemesiz, pingsiz sadece port taraması, verbose olarak iki kat detay, işletim sistemi taraması, portların arkasında çalışan servislerin versiyonlarını bana çıkar, script olarak; smb-enum’la başlayan tüm scriptleri kullan ayrıca smb-ls, smb-os-discovery kullan ve smb-s’le başlayan tüm scriptleri de kullan ve bunları verilen IP adresi üzerinde gerçekleştir.
- `nmap -p80 —script http-unsafe-output-escaping abc.com`
    - domain üzerindeki 80. portlar üzerinde verilen script’i uygula. (script: çıktıdan kaçan, görünmekten kaçan sorunları listelemeye çalışan scripttir.)
- `nmap -p445 —script smb-vuln-ms17-010 192.168.1.1`
    - port 445 üzerinde smb-vuln-ms17-010(güvenlik açığı var mı yok mu kontrolü yapar) scriptini uygula *(port 445:smb portudur)*
- `nmap -f -T0 -n -Pn —data-length 200 -D RND:10 192.168.1.1`
    - fragmentation (parçalı olarak tara) en yavaş ayarlar dns çözümlemesi yapma pingsiz port tara arada bir gönderilen paketler ek olarak 200 byte ekle, Deckoy IP’ler kullan ama bunları random şekilde seç 10 tane IP ile yapıyoruz.
- `nmap -T4 -sV —version-all —oscan-guess -A -p 1-1000 192.168.1.1 -oN sonuc.txt`
    - 4 hızında bir tarama yapıyoruz port altında çalışan servislerin versiyonlarını çıkartmak istiyoruz, en hassas şekilde almak istiyoruz. İşletim sistemi bilgisini en agresif şekilde kullan. İşletim sistemi hakkında biraz daha saldırgan ol port olarak 1-1000 arası portları tara. ve sonuçları şuraya yazdır: sonuç.txt

## Scriptlerden yardım alma:

“/usr/share/nmap/scripts/” klasörünün içinde bulunurlar.

`ls -l /usr/share/nmap/scripts/ | grep http` ⇒ grep komutu ile aradığımız scripti buluyoruz.

yada:

`locate *.nse`

`locate *http*.nse`  ”*” işareti önünde veya arkasına gelirse; önünde veya arkasında herhangi bir şey olabilir anlamına gelir.

## NSE ile NetBIOS discovery

makineleri hostname (isimlerini) netBIOS üzerinden yakalamaya çalışıyoruz. 

`nmap —script nbstat 10.10.10.11-12`

- bu gibi işlemlerde portlara bakmak daha mantıklı olacaktır.

<aside>
💡 netBIOS UDP:137 TCP:139 bu portlarda çalışır.

</aside>

`nmblookup -A 10.10.10.11` 

- mac adresini ve makine ismini yakalayabilir.

## NSE ile SMB Enumeration

**SMB:** Server Message Block

| nmap —script smb-os-discovery “hedef_ip/domain” -p445 | teknolojiyi keşfetmeye çalışır, ip adresinin kime ait olduğunu ortaya çıkartır. |
| --- | --- |
| nmap —script smb-security-mode 10.10.10.11 -p445 | güvenlik açığı yakalar. |
| nmap —script smb-brute 10.10.10.11 -p445 | hedefin k.adı ve şifreyi verir. |
| nmap —script smb-enum-user 10.10.10.11 -p445 | userları gösterir |
| nnamp —script smb-enum-shares 10.10.10.11 -p445 | paylaşılan dosyaları getirir. |
| nmap —script-args smbuser=administrator, smbpass= ‘’  | argüman kullanabiliriz bu bizim içeriye giriş için açık arama metodlarımızdan bir tanesi, kısaca: 
“içeriye girerken administrator profilinin şifresinin boş olup olmadığına bak” dendi. |
| smbclient -L 10.10.10.11 | hedef smb sunucusu ile konuşabilen bir smb istemcisidir. -L parametresi ile listeleme yapar.
Listeleme yaparken root şifresini ister (karşı tarafınkini) bilinmiyorsa -N parametresi kullanılır. |
| smbclient \\\\10.10.10.11\\IPC$ -N | “\” ⇒ içeri girmek istediğimizi söylüyoruz, daha sonra ise konum veriyoruz; “IPC$” konumdur. |

nmap bazen script’leri okurken hata verir. bu gibi durumlarda detayları öğrenebilmek adına debug alırız “`-d`”

| nmap 10.10.10.11 -p3306 —script mysql-databases —script-args mysqluser=root -d | mysqlp veritabanından argüman olarak user’ı kullandık bu da bizi root kullanıcısına götürür password vermedik çünkü password olmadığını keşfetmiştik,  -d ile de debug(ayrıntılara) bakıyoruz. |
| --- | --- |

## NSE ile SSH Enumeration

**ssh portu:** 22

`nmap -p22 10.10.10.13 —script banner`

- karşılama mesajı çıkartmaya çalışır.

`nmap -p22 10.10.10.13 —script ssh-auth-methods`

- ssh doğrulama metodlarını denetiyoruz.

`nmap -p22 10.10.10.13 —script ssh-hostkey`

- hostkey’lere bakar.

`nmap -p22 10.10.10.13 —script ssh-hostkey —script-args ssh_hostkey=full`

- hostkey’lerin açılmış hallerini gösterir.

`nmap -p22 10.10.10.13 —script ssh-hostkey —script-args ssh_hostkey=all`

- hostkey’lerin image karşılığını verir.

`nmap -p22 10.10.10.13 —script ssh-publickey-acceptance -d`

- debug ile detaylı bakıyor ve nmap’e saldırması için talimat veriyoruz.

`nmap-p22 10.10.10.13 —script ssh-brute —script-args userdb=”/root/Desktop/users.txt”.passdb=”/root/Desktop/pass.txt”`

- bizim oluşturduğumuz user ve password txt dosyalarını olaya dahil edip brute-force attack deniyoruz.
    
    **en sona `unpwdb.timelimit=15` yazarsak, zaman belirler dakika cinsinden.**
    

## NSE ile HTTP Enumeration

**http portu:** bilinen 80 ve 443’te çalışır ama yine de ilk önce hepsini taratmamızda fayda var.

`nmap -p- 10.10.10.13 -T4 -sV` 

- http portlarını bulduktan sonra versiyonları da istedik.

`nmap -p 8020,8022,8080,8282,8484,8585 10.10.10.13 -T4 -sV --script http-methods`

- Portları bulunduktan sonra, o portları açmayı deniyoruz ve açılan kısımların versiyonları ve bu portlar üzerinde hangi http methodlarını uygulayabileceğimizi soruyoruz.

![GET, HEAD, POST, PUT, DELETE, OPTIONS http metodlarıdır. ](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/7f061b30-bf17-495b-b081-182df6f264e1/Adsz.png)

GET, HEAD, POST, PUT, DELETE, OPTIONS http metodlarıdır. 

server ve client arasında http bağlantısı gerçekleştiğinde soketler açılır. browser ve server arasında da soketler konuşur. HTTP request, HTTP response mesajları gider, gelir.

**GET:**

Bir objeyi okumak istediğimizi söylüyoruz. Web sayfasının Body’sini çeker.

**HEAD:**

Web Sitesinin Header’ını çeker.

**POST:**

Oluştur manasındadır. Bir veri oluştururuz.

**PUT:**

Put ve Patch’te vardır, bu ikisi güncelleme yapar. Herhangi bir veri üzerinde güncelleme işlemi gerçekleştirir.

**DELETE:**

Silme işlemi gerçekleştirir.

**OPTIONS:**

HTTP metodları nelerdir diye sorarız, OPTIONS’la yapabileceğimiz HTTP metodlarını öğreniriz.

**TRACE:**

Takip ve Teşhis içindir. Gönderdiğimiz istek aynı şekilde cevaplanır. Bu değiştiriliyorsa arada bir yönlendirme/proxy olduğunu anlarız.

**—scripttan sonra yazılacaklar:**

| http-config-backup | ayar yedekleri (backupları) var mı? |
| --- | --- |
| http-auth-finder | authentication metodlarını bul. |
| http-backup-finder | yedekler varsa onları bul. |
| http-apache-server-status | apache server durumu |
| http-brute | brute attack yaptırıyoruz. |
| http-php-version | php versiyonu varsa onu da çıkar |
| http-security-headers | güvenlik başlıkları |
| http-slowloris-check | slowloris’i kontrol et.
slowloris: çok fazla bağlantı isteği gönderilir. sunucu bu istekleri açık bırakırsa, yeni isteklere cevap veremez hale gelir. |
| http-userdir-enum | <dir>user</dir> içerisine baktırdık. |
| http-erros | http hatalarına bak. |
| http-vuln* | güvenlik açığı taratma şekli “*” hepsini tarıyodu, kişisel tarama için ise; http-vuln-cve |

## NSE ile Güvenlik Açığı ve CVE Tespiti

böyle yoğun tarama yapacağımız zaman, versiyon bilgilerini de almakta fayda vardır.

`nmap 10.10.10.13 -p- -sV -T4 -vvv ~/Desktop/scriptvuln.txt —script vuln`

![detaylı verbose isteyerek güvenlik açığı arıyor, sonrasında da masaüstüne txt dosyayı olarak atıyoruz.](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/486a5e46-f265-4273-a25d-43f500c6cea9/Adsz.png)

detaylı verbose isteyerek güvenlik açığı arıyor, sonrasında da masaüstüne txt dosyayı olarak atıyoruz.

`nmap 10.10.10.13 -p- -sV -T4 -vvv ~/Desktop/scriptvulners.txt —script vulners`

## NMAP Vulscan ile Güvenlik Açığı ve CVE TESPİTİ

öncelikle githubtan vulscan ile ilgili repoyu indirmemiz gerekiyor:

 [https://github.com/scipag/vulscan](https://github.com/scipag/vulscan)

daha sonra ise bunun kurulumunu yapıyoruz, vulscan klasöründen utilities, updater;

`chmod +x updateFiles.sh`

`./updateFiles.sh`

nmap’in içine yeni bir script dosyası yazdığımız zaman, updatedb’yi kullanmamız gerekiyor.

`nmap —script-updatedb`

---

vulscan bize bir klasör olarak geldiği için çalıştırırken onu o şekilde göstermemiz gerekiyor.

`nmap -sV -p- -T4 10.10.10.11 -vvv —script vulscan/vulscan.nse`

---
