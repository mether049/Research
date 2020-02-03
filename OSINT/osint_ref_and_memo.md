# OSINT Tools
### OS/VM

|OS/VM|remarks|
|:-|:-|
|[Buscador OSINT VM](https://inteltechniques.com/buscador/)|IntelTechniques提供<br>Buscador(ブスカドル，スペイン語：先駆者・開拓者)<br>多くのOSINTツールが実装されたOSINT用のVM|
|[whonix](https://www.whonix.org/)|インターネットTorを経由only<br>[Kicksecure](https://www.whonix.org/wiki/Kicksecure)<br>キーストローク匿名化<br>AnboxによるAndroidアプリケーションの実行|
|[Tails](https://tails.boum.org/)|インターネットTorを経由only<br>USBやDVDからの起動を前提|
|[Qubes OS](https://www.qubes-os.org/)|Xenを利用して全てのアプリケーションを独立して実行<br>Template VMにwhonixを利用することができ，より匿名性を高めることが可<br>Template VMは複数のOS(Windows,Fedora,Whonix,Debian,etc.)を同時に利用することが可|

### General Tools
- [Maltego](https://www.paterva.com/downloads.php)
- [FinalRecon](https://github.com/thewhiteh4t/FinalRecon)
- [Recon-ng](https://github.com/lanmaster53/recon-ng)
- [OWASP Maryam](https://github.com/saeeddhqan/Maryam)
- [Photon](https://github.com/s0md3v/Photon)
- [Maryam](https://github.com/saeeddhqan/Maryam)
- [URLhaus monitor](https://github.com/ninoseki/urlhaus_monitor)
- [DDIR](https://github.com/nenaiko-dareda/DDIR)
- [dnstwist](https://github.com/elceef/dnstwist)
- [CERTSTREAM](https://certstream.calidog.io/)
- [Phishing Catcher](https://github.com/x0rz/phishing_catcher)
- [Apullo](https://github.com/ninoseki/apullo)
- [Mihari](https://github.com/ninoseki/mihari)
- [InQuest/ThreatIngestor](https://github.com/InQuest/ThreatIngestor)
- [Mimir](https://github.com/deadbits/mimir)

# Crawler
### malware
- [ph0neutria](https://github.com/phage-nz/ph0neutria)
- [mwcrawler](https://github.com/0day1day/mwcrawler)
- [Ragpicker](https://github.com/robbyFux/Ragpicker)

# Search Engine
### Google
- [Google Advanced Search](https://www.google.com/advanced_search)
    - 検索オプションを詳細に設定して検索
- filetype:
    - ファイル形式を指定して検索
> filetype:pdf
- site:
    - ドメインを指定(サブドメイン，TLD，SLD，path，etc.)して検索
> site:exmaple.com
- inurl:
    - URL内のテキスト(param,protocol,filename)を検索
> site:example.com inurl:https
- -(hyphen)
    - 除外
> -inurl:http -inurl:hogehoge
- ""(double quotation)
    - 完全一致
> "aa bb"
- or
    - または
> aa or bb
- *(asterisk)
    - ワイルドカード
> "a*z"
- X..Y
    - 数値の範囲
> "top 1..10"
- ~(tilde)
    - 関連キーワードを含んだ検索
> ~hogehoge
- intitle:
    - ページタイトルのテキストを検索
- intext:
    - ページ本文のテキストを検索
- related:
    - 類似ドメインの検索
> related:example.com
- cache:
    - キャッシュの検索
> chache:example.com



# Domain, IP, URL, File hash, CVE Research
- ※空欄は調査中(更新予定)

|name|input|API|remarks|
|:-|:-|:-|:-|
|[urlscan.io](https://urlscan.io/)|url,ip,domain,hash,ASN|〇||
|[RiskIQ](https://www.riskiq.com/products/community-edition/)|domain,ip,url,hash,email,certificates|〇||
|[IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)|domain,url,IP,md5,hash tag,cve,application name|〇||
|[VirusTotal](https://www.virustotal.com/gui/home/upload)|url,hash,IP|〇||
|[Censys](https://censys.io/)|ip,domain,url,certificates|〇||
|[SHODAN](https://www.shodan.io/ip)||〇||
|[Alien Vault](https://otx.alienvault.com/)|domain,url,ip,hash,email,yara,cve,mutex,etc.|〇||
|[PhishTank](https://www.phishtank.com/index.php)|url|〇||
|[ANYRUN](https://app.any.run/submissions)|domain,ip,url,hash,MITRE ATT&CK technique ID,Suricata ID||online sandbox|
|[URLhaus](https://urlhaus.abuse.ch/browse/)|domain,ip,url,hash|||
|[Web Insight](http://webint.io/)|url|||
|[ThreatMiner](https://www.threatminer.org/index.php)|domain,ip,url,hash,email,ssl,UA,apt name,malware family,registry,mutex,etc.|||
|[Threats Crowd](https://www.threatcrowd.org/)|domain,ip,url,email,organization||powered byAlienVault|
|[MX TOOLBOX](https://mxtoolbox.com/blacklists.aspx)|ip,domain|||
|[pastebin](https://pastebin.com/)|keyword|||
|[HYBRID ANALYSIS](https://www.hybrid-analysis.com/)|domain,ip,url,hash,yara,string||online sandbox|
|[cape sandbox](https://cape.contextis.com/analysis/search/)|domain,ip,url,hash,command,malware family,registry,mutex,string||online sandbox|
|[JOESandbox Cloud](https://www.joesandbox.com/#advanced)|domain,ip,hash,hash tag||online sandbox|
|[Vulmon](https://vulmon.com/)|cve,company,product|||
|[IntelligenceX](https://intelx.io/)|domain,ip,url,email,bitcoin address,etc.|||
|[NerdyData](https://nerdydata.com/)|||https://www.bellingcat.com/resources/how-tos/2015/07/23/unveiling-hidden-connections-with-google-analytics-ids/|
|[SpyOnWeb](http://spyonweb.com/)|domain,ip,url|||
|[aguse](https://www.aguse.jp/)|url,email|||
|[DomainBigData](https://domainbigdata.com/)|domain,ip,url,registrant name,email|||
|[DN pedia](https://dnpedia.com/tlds/search.php)|domain|||
|[Robtex](https://www.robtex.com/)|domain,ip,url,as number|||
|[nccgroupnumber](https://labs.nccgroup.trust/typofinder/)|domain||researching typosquatting|
|[VX Vault](http://vxvault.net/ViriList.php)|ip,url,hash|||
|[VMRAY ANALYZER](https://www.vmray.com/analyzer-malware-sandbox-free-trial/?utm_campaign=reports&utm_source=vmray&utm_medium=analysis2&utm_content=report)||||
|[malwareurl](https://www.malwareurl.com/listing-urls.php)|domain,ip,url|||
|[dedoLa](http://dedola.eu/malware.php)||||
|[SPLOITUS](https://sploitus.com/)|cve,applicationname||researching poc|
|[Feodo Tracker](https://feodotracker.abuse.ch/browse/)|ip|||
|[MalShare](https://malshare.com/)|hash,yara|||
|[ZoomyEye](https://www.zoomeye.org/)|domain,ip,country,etc.|||
|[FOFA](https://fofa.so/)|domain,ip,country,etc.|||
|[ONYPHE](https://www.onyphe.io/)|domain,country,etc.|||
|[PublicWWW](https://publicwww.com/)|domain,ip,keyword,code snippet,tld,etc.|||
|[Twitter IOC Hunter](http://tweettioc.com/search)|domain,ip,url,hash,email,user,hash tag|〇||
|[Wayback Machine](https://archive.org/web/)|url||archive|
|[Stanford Web Archive Portal](https://swap.stanford.edu/)|url||archive||
|[UK Parliament Web Archive](http://webarchive.parliament.uk/)|url||archive||
|[Library of Congress](https://www.loc.gov/)|url||archive||
|[totalhash](https://totalhash.cymru.com/search/)|domain,ip,hash,urll,UA,email,mutex,registry|||
|[IP & Domain Reputation Center](https://talosintelligence.com/reputation_center)|domain,ip,hash|||
|[GREYNOISE](https://viz.greynoise.io/)||〇|検索機能が豊富<br>malicious判定された機器のみの検索等が可能|
|[INQUEST LABS](https://labs.inquest.net/)||〇||
|[Koodous](https://koodous.com/)|||android only||
|[BinaryEdge](https://www.binaryedge.io/)||||
|[Cryptolaemus Pastedump](https://paste.cryptolaemus.com/)|||主にEmotetのIoCを掲載|
|[virusbay](https://beta.virusbay.io/sample/browse)||||
|[VisualSitemaps](https://visualsitemaps.com/)|URL||サイトマップを取得|
|[maltiverse](https://maltiverse.com/search)|domain,ip,url,hash,entropy,tld,keyword|||
|[malwareworld](https://malwareworld.com/)|domain,ip|||

# ref:
- [OSINT Cheat-Sheat,2019](https://inteltechniques.com/JE/OSINT_Packet_2019.pdf)
