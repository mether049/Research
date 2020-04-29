# OSINT Tools
### OS/VM

|OS/VM|remarks|
|:-|:-|
|[Buscador OSINT VM](https://inteltechniques.com/buscador/)|IntelTechniques提供<br>Buscador(ブスカドル，スペイン語：先駆者・開拓者)<br>多くのOSINTツールが実装されたOSINT用のVM|
|[whonix](https://www.whonix.org/)|インターネットはTorを経由only<br>[Kicksecure](https://www.whonix.org/wiki/Kicksecure)<br>キーストローク匿名化<br>AnboxによるAndroidアプリケーションの実行|
|[Tails](https://tails.boum.org/)|インターネットはTorを経由only<br>USBやDVDからの起動を前提|
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
- [spiderfoot](https://github.com/smicallef/spiderfoot)
- [OSINT Framework](https://osintframework.com/)
- [Sifter](https://github.com/s1l3nt78/sifter)

# Crawler
### malware
- [ph0neutria](https://github.com/phage-nz/ph0neutria)
- [mwcrawler](https://github.com/0day1day/mwcrawler)
- [Ragpicker](https://github.com/robbyFux/Ragpicker)
### Directory Search
- [Dirhunt](https://github.com/Nekmo/dirhunt)

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
- Custom Google検索集
    - マルウェア検索用
        - [Decalage](http://decalage.info/mwsearch#gsc.tab=0)
    - pastesite検索用
        - https://cse.google.com/cse?cx=006896442834264595052:fawrl1rug9e

# Domain, IP, URL, File hash, CVE Research
- ※空欄は調査中(更新予定)

|name|input|API|remarks|
|:-|:-|:-|:-|
|[urlscan.io](https://urlscan.io/)|url,ip,domain,hash,ASN|〇||
|[RiskIQ](https://www.riskiq.com/products/community-edition/)|domain,ip,url,hash,email,certificates|〇||
|[IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)|domain,url,IP,md5,hash tag,cve,application name|〇||
|[VirusTotal](https://www.virustotal.com/gui/home/upload)|url,hash,IP|〇|[vti-dorks](https://github.com/Neo23x0/vti-dorks)<br>[Antivirus Event Analysis Cheat Sheet](https://cse.google.com/cse?cx=003248445720253387346:turlh5vi4xc)<br>[VT Hunting](https://github.com/fr0gger/vthunting)|
|[Censys](https://censys.io/)|ip,domain,url,certificates|〇||
|[SHODAN](https://www.shodan.io/ip)||〇|[Shodan search 101](https://ninoseki.github.io/2020/04/01/shodan-101.html)|
|[Alien Vault](https://otx.alienvault.com/)|domain,url,ip,hash,email,yara,cve,mutex,etc.|〇||
|[PhishTank](https://www.phishtank.com/index.php)|url|〇||
|[ANYRUN](https://app.any.run/submissions)|domain,ip,url,hash,MITRE ATT&CK technique ID,Suricata ID||online sandbox|
|[URLhaus](https://urlhaus.abuse.ch/browse/)|domain,ip,url,hash|〇||
|[Web Insight](http://webint.io/)|url|||
|[ThreatMiner](https://www.threatminer.org/index.php)|domain,ip,url,hash,email,ssl,UA,apt name,malware family,registry,mutex,etc.|〇||
|[Threats Crowd](https://www.threatcrowd.org/)|domain,ip,url,email,organization|〇|powered byAlienVault|
|[MX TOOLBOX](https://mxtoolbox.com/blacklists.aspx)|ip,domain|〇||
|[pastebin](https://pastebin.com/)|keyword|〇|Pastebinに投稿された内容をyaraでスキャンし通知するアプリケーションとして[PasteHunter](https://github.com/kevthehermit/PasteHunter)がある|
|[HYBRID ANALYSIS](https://www.hybrid-analysis.com/)|domain,ip,url,hash,yara,string|〇|online sandbox|
|[cape sandbox](https://cape.contextis.com/analysis/search/)|domain,ip,url,hash,command,malware family,registry,mutex,string|〇|online sandbox|
|[JOESandbox Cloud](https://www.joesandbox.com/#advanced)|domain,ip,hash,hash tag,yara|〇|online sandbox|
|[Vulmon](https://vulmon.com/)|cve,company,product|||
|[IntelligenceX](https://intelx.io/)|domain,ip,url,email,bitcoin address,etc.|〇||
|[NerdyData](https://nerdydata.com/)||〇|https://www.bellingcat.com/resources/how-tos/2015/07/23/unveiling-hidden-connections-with-google-analytics-ids/|
|[SpyOnWeb](http://spyonweb.com/)|domain,ip,url|〇|同じgoogle-analytics識別子，google-adsense識別子を利用するドメインを検索できる|
|[aguse](https://www.aguse.jp/)|url,email|||
|[DomainBigData](https://domainbigdata.com/)|domain,ip,url,registrant name,email|||
|[DN pedia](https://dnpedia.com/tlds/search.php)|domain|||
|[Robtex](https://www.robtex.com/)|domain,ip,url,as number|〇||
|[nccgroupnumber](https://labs.nccgroup.trust/typofinder/)|domain||researching typosquatting|
|[VX Vault](http://vxvault.net/ViriList.php)|ip,url,hash|||
|[VMRAY ANALYZER](https://www.vmray.com/analyzer-malware-sandbox-free-trial/?utm_campaign=reports&utm_source=vmray&utm_medium=analysis2&utm_content=report)||||
|[malwareurl](https://www.malwareurl.com/listing-urls.php)|domain,ip,url|||
|[dedoLa](http://dedola.eu/malware.php)||||
|[SPLOITUS](https://sploitus.com/)|cve,applicationname||researching poc|
|[Feodo Tracker](https://feodotracker.abuse.ch/browse/)|ip|〇||
|[MalShare](https://malshare.com/)|hash,yara|〇||
|[ZoomyEye](https://www.zoomeye.org/)|domain,ip,country,etc.|〇||
|[FOFA](https://fofa.so/)|domain,ip,country,etc.|〇||
|[ONYPHE](https://www.onyphe.io/)|domain,country,etc.|〇||
|[PublicWWW](https://publicwww.com/)|domain,ip,keyword,code snippet,tld,etc.|〇||
|[Twitter IOC Hunter](http://tweettioc.com/search)|domain,ip,url,hash,email,user,hash tag|〇||
|[Wayback Machine](https://archive.org/web/)|url|〇|archive|
|[Stanford Web Archive Portal](https://swap.stanford.edu/)|url||archive||
|[UK Parliament Web Archive](http://webarchive.parliament.uk/)|url||archive||
|[Library of Congress](https://www.loc.gov/)|url||archive||
|[totalhash](https://totalhash.cymru.com/search/)|domain,ip,hash,urll,UA,email,mutex,registry|〇||
|[IP & Domain Reputation Center](https://talosintelligence.com/reputation_center)|domain,ip,hash|||
|[GREYNOISE](https://viz.greynoise.io/)||〇|検索機能が豊富<br>malicious判定された機器のみの検索等が可能|
|[INQUEST LABS](https://labs.inquest.net/)||〇||
|[Koodous](https://koodous.com/)|file,yara||android only||
|[BinaryEdge](https://www.binaryedge.io/)||〇||
|[Cryptolaemus Pastedump](https://paste.cryptolaemus.com/)|||主にEmotetのIoCを掲載|
|[virusbay](https://beta.virusbay.io/sample/browse)||||
|[VisualSitemaps](https://visualsitemaps.com/)|URL||サイトマップを取得|
|[maltiverse](https://maltiverse.com/search)|domain,ip,url,hash,entropy,tld,keyword|〇||
|[malwareworld](https://malwareworld.com/)|domain,ip|||
|[unfurl](https://dfir.blog/unfurl/)|url|||
|[Parse User Agents](https://developers.whatismybrowser.com/)|user-agent|〇|User-Agentのパーサ|
|[httpstatus](https://httpstatus.io/)|url||check status codes, response headers, and redirect chains.|
|[DownDetector](https://downdetector.jp/)|keyword|〇|障害発生などの確認|
|[AbuseIPDB](https://www.abuseipdb.com/)|ip|〇||
|[Cybercrime tracker](https://cybercrime-tracker.net/)|url,keyword|||
|[DomainWatch](https://domainwat.ch/)|domain,phone-number,mail,etc.|〇||
|[DNSdumpster](https://dnsdumpster.com/)|domain|||
|[dns ninja](https://www.dns.ninja/)|domain|||
|[SecurityTrails](https://securitytrails.com/)|domain,hosname,ip,keyword|〇||
|[Find Subdomains](https://findsubdomains.com/)|domain|〇||
|[Threat DB](https://labs.cloudbric.com/threatdb)|Wallet address,IP,URL|||
|[Find Subdomain](https://pentest-tools.com/information-gathering/find-subdomains-of-domain)|domain|||
|[SUCURI](https://sitecheck.sucuri.net/)|domain,url|||
|[SecURL](https://securl.nu/)|URL|||
|[SSL Sever Test](https://globalsign.ssllabs.com/)|hostname|||
|[crt.sh](https://crt.sh/)|domain,certificates|||
|[gred](http://check.gred.jp/)|url|||
|[malwares.com](https://www.malwares.com/)|domain,ip,url,hash,hostname,tag|〇||
|[ViruSign](https://www.virusign.com/home.php)|hash,keyword|||
|[virusbay](https://beta.virusbay.io/sample/browse)|hash,tag|||
|[TrackingTheTrackers](https://trackingthetrackers.com/)|URL||サードパーティートラッカーのファーストパーティーへの偽装を判別，送信されるCookie情報の確認|
|[MalwareBazaar](https://bazaar.abuse.ch/browse/)|hash,tag,keyword|〇|download可<br>マルウェアサンプルを共有することを目的としたabuse.chのプロジェクト|
|[SSLBL](https://sslbl.abuse.ch/)|hash,keyword(malware),date|〇|c2通信に利用されるSSL証明書の検索|
|[Bot Invaders Realtime Tracker](http://www.marc-blanchard.com/BotInvaders/index.php)|-|〇|DGAのTracker|
|[malinfo](https://www.malinfo.co.kr/cti/)|domain,ip,file|||
|[sublime-security/static-files@github](https://github.com/sublime-security/static-files)|||Alexa top 1M,Ambrella top 1M,freemailのドメイン，free file host,短縮URL等の一覧を掲載|
|[useragentstring](http://useragentstring.com/index.php)|User-Agent||user-agentのパーサ|
|[VxCube](http://vxcube.com/)|domain,ip,url,hash,file,tag|〇||
|[Paste Site Search](https://netbootcamp.org/pastesearch.html#gsc.tab=0)|keyword||複数のpastesiteから検索|
|[Expired Domains.net](https://www.expireddomains.net/)|domain||Expired Domain Name Search Engine|
|[CRDF Threat Ceneter](https://threatcenter.crdf.fr/)|domain,url,hash,keyword|〇||

# yara source
- https://github.com/advanced-threat-research/Yara-Rules
- [malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
- https://github.com/Yara-Rules/rules
- https://github.com/JPCERTCC/MalConfScan/blob/master/yara/rule.yara
- https://github.com/ctxis/CAPE/tree/master/data/yara/CAPE
- https://github.com/Neo23x0/signature-base/tree/master/yara
- https://github.com/ProIntegritate/Yara-rules
- https://github.com/k-vitali/Malware-Misc-RE

# IoC source
- https://github.com/StrangerealIntel/CyberThreatIntel
- https://github.com/Neo23x0/sigma
- https://github.com/karttoon/iocs
- https://github.com/stamparm/maltrail/tree/master/trails/static
- https://github.com/malwareinfosec/EKFiddle/blob/master/Regexes/MasterRegexes.txt

# MindMaps
- https://github.com/sbousseaden/Slides/tree/master/Hunting%20MindMaps
- https://github.com/caschnee/misp-use-cases/blob/master/MISP_use_cases_detailed.png

# Corpus
- https://vx-underground.org/packs.html
- https://github.com/ytisf/theZoo
- https://github.com/ActorExpose/PhishKits

# ref:
- [OSINT Cheat-Sheat,2019](https://inteltechniques.com/JE/OSINT_Packet_2019.pdf)
- [Download OSINT Bookmarks@OSINT Combine](https://www.osintcombine.com/osint-bookmarks)
    - OSINTに有用なWebサイトをまとめたBookmarkを提供
- [普段の調査で利用するOSINTまとめ,qiita,2020-03](https://qiita.com/00001B1A/items/4d8ceb53993d3217307e)
