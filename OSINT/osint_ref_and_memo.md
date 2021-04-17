※OSINT以外につても当該ページにまとめる可能性あり
# OSINT Tools
### OS/VM
|OS/VM|remarks|
|:-|:-|
|[Buscador OSINT VM](https://inteltechniques.com/buscador/)|IntelTechniques提供<br>Buscador(ブスカドル，スペイン語：先駆者・開拓者)<br>多くのOSINTツールが実装されたOSINT用のVM|
|[whonix](https://www.whonix.org/)|インターネットはTorを経由only<br>[Kicksecure](https://www.whonix.org/wiki/Kicksecure)<br>キーストローク匿名化<br>AnboxによるAndroidアプリケーションの実行|
|[Tails](https://tails.boum.org/)|インターネットはTorを経由only<br>USBやDVDからの起動を前提|
|[Qubes OS](https://www.qubes-os.org/)|Xenを利用して全てのアプリケーションを独立して実行<br>Template VMにwhonixを利用することができ，より匿名性を高めることが可<br>Template VMは複数のOS(Windows,Fedora,Whonix,Debian,etc.)を同時に利用することが可|

### generic Tools
- [Maltego](https://www.paterva.com/downloads.php)
    - Maltegoのチュートリアル
         - [Tutorial](https://www.maltego.com/categories/tutorial/)
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
  - ツリー構造になっており目的合わせてノードを選択することで必要なOSINTツールやサイトを探すことが可能
- [Sifter](https://github.com/s1l3nt78/sifter)
- [vps_setup for recon](https://github.com/nullenc0de/vps_setup/blob/master/offensive_script.sh)
- [crtsh](https://github.com/knqyf263/crtsh)
- [GetOldTweets-python](https://github.com/Jefferson-Henrique/GetOldTweets-python)
- [theHarvester](https://github.com/laramies/theHarvester)
- [Creepy](https://www.geocreepy.com/)
   - 各種SNSから地理的情報を取得
- [WebShag](https://www.openvas.org/)
   - Port Scan,URL Scan ,Crawler, File Fuzzing
- [OpenVAS](https://github.com/wereallfeds/webshag)
   - OSSの脆弱性スキャナ
- [Unicornscan](https://github.com/dneufeld/unicornscan)
   - スキャナ
- [fierce](https://github.com/mschwager/fierce)
- [CloudFlair](https://github.com/christophetd/CloudFlair)
- [cloudsnare](https://gist.github.com/chokepoint/28bed027606c5086ed9eeb274f3b840a)
- [CloudBunny](https://github.com/Warflop/CloudBunny)
- [Bypass firewalls by abusing DNS history](https://github.com/vincentcox/bypass-firewalls-by-DNS-history)
    - ref:
        - [オリジンIPの特定によるクラウド型WAFのバイパス](https://akaki.io/2019/cloud-waf_bypass)
- [Malwoverview](https://github.com/alexandreborges/malwoverview)
- [OSINT Recon Tool](https://recontool.org/#mindmap)
- [grab_beacon_config](https://github.com/whickey-r7/grab_beacon_config)
    - nmap用,cobaltstrikeのconfig情報収集
- [xeuledoc](https://github.com/Malfrats/xeuledoc)
    - public google documentから情報を収集

## SNS
- TweetDeck
    - 各キーワード，ユーザ等に関する検索結果をカラムごとに表示することができる
- [Deck For Reddit](https://rdddeck.com/)
    - TweetDeckのRddit版みたなもの
- [tafferugli](https://github.com/sowdust/tafferugli)
    - twitter分析フレームワーク
- ユーザID(Facebook,Twitter,Instagram)の見つけ方
    - https://www.aware-online.com/en/importance-of-user-ids-in-social-media-investigations/
    


# Crawler
### malware
- [ph0neutria](https://github.com/phage-nz/ph0neutria)
- [mwcrawler](https://github.com/0day1day/mwcrawler)
- [Ragpicker](https://github.com/robbyFux/Ragpicker)
### Directory Search
- [Dirhunt](https://github.com/Nekmo/dirhunt)
### Others
- [CIRCL AIL](https://github.com/ail-project/ail-framework/)
  - 情報漏洩分析フレームワーク

# Search Engine
### Google
- [Google Advanced Search](https://www.google.com/advanced_search)
    - 検索オプションを詳細に設定して検索
- filetype:
    - ファイル形式を指定して検索
> filetype:pdf
- ext:
    - 拡張子を指定して検索
> ext:log
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
- ref:
 - [advanced_operators_reference@googleguide.com](http://www.googleguide.com/advanced_operators_reference.html)
 - [Google advanced power search url request parameters](https://stenevang.wordpress.com/2013/02/22/google-advanced-power-search-url-request-parameters/)
- Custom Google検索集
    - マルウェア関連検索用
        - [Decalage](http://decalage.info/mwsearch#gsc.tab=0)
    - pastesite検索用
        - https://cse.google.com/cse?cx=006896442834264595052:fawrl1rug9e
        - https://netbootcamp.org/pastesearch.html#gsc.tab=0
- Google Dorks(Google Hacking)
    - Google検索等を利用してGoogleにindexされた脆弱なシステムを探したり，必要な情報を入手するための技術や検索クエリ
     - 例：Opendir,機密情報・システムの設定情報・他不適切に公開されているファイル，IoT機器やサーバのログイン画面，特定の脆弱性の対象となるサーバ，etc.
    - ref:
        - [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)
        - [Listing of a number of useful Google dorks.](https://gist.github.com/stevenswafford/393c6ec7b5375d5e8cdc)
        - [Google Dorksを使った脆弱なサービスの検索方法－２](https://infoshield.co.jp/blog/security-news/20200221-701/)
        - [Find Vulnerable Services & Hidden Info Using Google Dorks \[Tutorial\]](https://www.youtube.com/watch?v=u_gOnwWEXiA)
### Yandex
- [25+ Yandex Search Operators Every Yandex User Should Know: A Complete List](https://seosly.com/yandex-search-operators/#10_Advanced_Yandex_Search_Operators)
    - Yandexの検索演算子について（GoogleとBingとの比較あり）

### Search for special symbols
- Googleでは`@＃$％^＆*（）= + [] \`の記号は無視される
- **[SymbolHound](http://symbolhound.com/advanced.php)**
  - Google検索と比較して記号を用いた検索が可能だが，インデックスされてるページが少ない印象
### Others
- 検索エンジン一覧
 - https://twitter.com/elhackernet/status/1374061815156510725
- [start.me](https://start.me/p/7kLY9R/osint-chine)
 - OSINT関連のリンク多数

# Regular expression
- [regexr.com](https://regexr.com/)
  - 正規表現を検証するためのオンラインサービス


# Domain, IP, URL, File hash, CVE, email, Name, etc. Research
- ※空欄は調査中(更新予定)

|name|input|API|remarks|
|:-|:-|:-|:-|
|[urlscan.io](https://urlscan.io/)|url,ip,domain,hash,ASN|〇|[task.source:certstream-suspicious](https://urlscan.io/search/#task.source%3Acertstream-suspicious)|
|[RiskIQ](https://www.riskiq.com/products/community-edition/)|domain,ip,url,hash,email,certificates|〇||
|[IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/)|domain,url,IP,md5,hash tag,cve,application name|〇||
|[VirusTotal](https://www.virustotal.com/gui/home/upload)|url,hash,IP|〇|[vti-dorks](https://github.com/Neo23x0/vti-dorks)<br>[Antivirus Event Analysis Cheat Sheet](https://www.nextron-systems.com/2019/10/04/antivirus-event-analysis-cheat-sheet-v1-7-2/)<br>[VT Hunting](https://github.com/fr0gger/vthunting)<br>https://pastebin.com/5j0TYLFi<br>[分析に利用しているSigma rule一覧](https://www.virustotal.com/ui/sigma_rules)|
|[Censys](https://censys.io/)|ip,domain,url,certificates|〇|[Censys Python Library](https://github.com/censys/censys-python)<br>https://www.hackers-arise.com/post/open-source-intelligence-osint-gathering-open-source-security-security-data-using-censys<br>regex使用可能|
|[SHODAN](https://www.shodan.io/ip)||〇|[Shodan search 101](https://ninoseki.github.io/2020/04/01/shodan-101.html)<br>[Shodan Command-Line Interface](https://cli.shodan.io/)<br>[Weaponizing favicon.ico for BugBounties , OSINT and what not](https://medium.com/@Asm0d3us/weaponizing-favicon-ico-for-bugbounties-osint-and-what-not-ace3c214e139)<br>[SHODAN Images](https://images.shodan.io/?query=Administrator&page=3)<br>hostnameで検索可能<br>[shodanをSQLで検索するためのプラグイン](https://hub.steampipe.io/plugins/turbot/shodan)<br>[beta版ではWebからhistoryが確認可能](https://beta.shodan.io/)|
|[Alien Vault](https://otx.alienvault.com/)|domain,url,ip,hash,email,yara,cve,mutex,etc.|〇||
|[PhishTank](https://www.phishtank.com/index.php)|url|〇||
|[ANYRUN](https://app.any.run/submissions)|domain,ip,url,hash,MITRE ATT&CK technique ID,Suricata ID||online sandbox<br>[[TUTORIAL] How to trick malware using ANY.RUN's TOR feature for fake location](https://www.youtube.com/watch?v=b9sbLwxv8I8&feature=emb_title)|
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
|[ZoomyEye](https://www.zoomeye.org/)|domain,ip,country,etc.|〇|[ZoomEye API](https://github.com/knownsec/ZoomEye)<br>[ZoomEye-Python](https://github.com/knownsec/ZoomEye-python)|
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
|[BinaryEdge](https://www.binaryedge.io/)|ip,keyword,etc.|〇|wildcard使用可能|
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
|[crt.sh](https://crt.sh/)|domain,certificates|〇|Certificate Transparency<br>https://github.com/knqyf263/crtsh|
|[gred](http://check.gred.jp/)|url|||
|[malwares.com](https://www.malwares.com/)|domain,ip,url,hash,hostname,tag|〇||
|[ViruSign](https://www.virusign.com/home.php)|hash,keyword|||
|[virusbay](https://beta.virusbay.io/sample/browse)|hash,tag|||
|[TrackingTheTrackers](https://trackingthetrackers.com/)|URL||サードパーティートラッカーのファーストパーティーへの偽装を判別，送信されるCookie情報の確認|
|[MalwareBazaar](https://bazaar.abuse.ch/browse/)|hash,tag,keyword|〇|download可<br>マルウェアサンプルを共有することを目的としたabuse.chのプロジェクト<br>yaraやシグネチャ名によるハンティング可能|
|[SSLBL](https://sslbl.abuse.ch/)|hash,keyword(malware),date|〇|c2通信に利用されるSSL証明書の検索|
|[Bot Invaders Realtime Tracker](http://www.marc-blanchard.com/BotInvaders/index.php)|-|〇|DGAのTracker|
|[malinfo](https://www.malinfo.co.kr/cti/)|domain,ip,file|||
|[sublime-security/static-files@github](https://github.com/sublime-security/static-files)|||Alexa top 1M,Ambrella top 1M,freemailのドメイン，free file host,短縮URL等の一覧を掲載|
|[useragentstring](http://useragentstring.com/index.php)|User-Agent||user-agentのパーサ|
|[VxCube](http://vxcube.com/)|domain,ip,url,hash,file,tag|〇||
|[Paste Site Search](https://netbootcamp.org/pastesearch.html#gsc.tab=0)|keyword||複数のpastesiteから検索|
|[Expired Domains.net](https://www.expireddomains.net/)|domain||Expired Domain Name Search Engine|
|[CRDF Threat Ceneter](https://threatcenter.crdf.fr/)|domain,url,hash,keyword|〇||
|[AZORult Tracker](https://azorult-tracker.net/)|domain,ip,as,status,etc.|〇|AZORultのc2トラッカー|
|[domain tools](https://whois.domaintools.com/)|domain,ip,ns,mail|〇|reverse-whois,reverse-ns|
|[Domain history checker](https://whoisrequest.com/history/)|domain,ip|〇||
|[Firefox Monitor](https://monitor.firefox.com/)|email|||
|[have i been pwned?](https://haveibeenpwned.com/)|email|〇||
|[DropCatch.com](https://www.dropcatch.com/)|domain||ドロップキャッチドメインの検索|
|[CheckUserNames](https://checkusernames.com/)|username|||
|[BeenVerified](https://www.beenverified.com/)|name,username,phone number,Address,VIN,email||multiple databases, bankruptcy records, career history, social media profiles and even online photosから得られる情報をレポート|
|[builtwith](https://builtwith.com/ja/)|url,keyword|〇|webサイトで使われれている技術(CMS,ソフトウェア,フォント,広告,etc)を調べることが可能|
|[BGPView](https://bgpview.io/)|AS number,IP|〇|AS関連の調査|
|[IPWatson](https://www.ipwatson.com/)|domain ip|〇|ハックされたサイトかどうかの情報あり|
|[Wappalyzer](https://www.wappalyzer.com/lookup)|url|〇|Webサイトで使われている技術情報を調べることが可能|
|[ICAN CZDS](https://czds.icann.org/home)||||ゾーンファイルの取得関連|
|[RIPEstat](https://stat.ripe.net/)|ip,asn,country code,host|〇|ip address prefixの変化やrouting historyの調査等に利用可能<br>[Flowspec – TA505’s bulletproof hoster of choice](https://blog.intel471.com/2020/07/15/flowspec-ta505s-bulletproof-hoster-of-choice/)|
|[RIPE Database Query](https://apps.db.ripe.net/db-web-ui/query)|keyword(e.g AS210138)||asnに関する超等に利用可能<br>[Flowspec – TA505’s bulletproof hoster of choice](https://blog.intel471.com/2020/07/15/flowspec-ta505s-bulletproof-hoster-of-choice/)|
|[dnstwister](https://dnstwister.report/)|domain||類似ドメインの検索|
|[Netcraft](https://sitereport.netcraft.com/)|url|||
|[ViewDNS.info](https://viewdns.info/iphistory/)|domain,mail,ip,ns,asn|〇|reverse-ns-lookup,reverse-whois,Chinese/Iran Firewall Test,|
|[CrimeFlare](http://www.crimeflare.org:82/cfs.html)|domain|〇||
|[hacker target](https://hackertarget.com/ip-tools/)|ip,domain,url|〇|Scan系，DNS系，Web系の多くのtoolがFreeで利用可能|
|[BinaryEdge](https://www.binaryedge.io/)||〇||
|[phishunt.io](https://phishunt.io/)||||
|[ipinfo.io](https://ipinfo.io/)|ip,asn|〇|type(ipsやbuisiness,etc),privacy(tor,proxy,vpn,hosting)判定してくれるのは便利|
|[Internet Health Report](https://ihr.iijlab.net/ihr/en-us)|asn,ixp|〇|https://eng-blog.iij.ad.jp/archives/6345|
|[ipip.net](https://en.ipip.net/)|ip|||
|[Hurricane Electric BGP Toolkit](https://bgp.he.net/)|ip,asn|||
|[ja3er.com](https://ja3er.com/form)|ja3|〇||
|[VirusBay](https://beta.virusbay.io/)|tag,hash||SOCアナリスト，マルウェアリサーチャのためのコラボレーションプラットフォーム|
|[Hathing Triage](https://tria.ge/s)|family,hash,yara,url,etc|〇|アップロードされた検体のファイル，メモリダンプに対してカスタムyaraでスキャンが可能（有償機能）|
|[WhoisXMLAPI](https://main.whoisxmlapi.com/)|ip,domain,ns|〇|reverse-ns,reverse-whois|
|[DNSlytics](https://dnslytics.com/)|domain,ip,ns,mx|〇|reverse-mx,reverse-ns|
|[DomainEye](https://domaineye.com/)|domain,ip,ns,mx,keyword|〇|reverse-mx,reverse-ns,reverse-whois|
|[tracker.viriback.com](http://tracker.viriback.com/)|domain,ip,url,keyword||c2 panel tracker|
|[ThreatShare](https://threatshare.io/malware/)|domain,ip,url,keyword||c2 panel tracker|
|[CyberCrime-tracker.net](https://cybercrime-tracker.net/)|domain,ip,url,keyword||c2  panel tracker|
|[benkow.cc](http://benkow.cc/passwords.php?)|domain,ip,url,keyword||c2 panel tracker|
|[dnstwist](https://dnstwist.it/)|domain|||
|[grayhatwarfare](https://shorteners.grayhatwarfare.com/)|url,domain,keyword,etc.||短縮URL<-->実際URLのデータベース|
|[ThreatFox](https://threatfox.abuse.ch/)|url,domain,ip,tag,family,reporter,etc.|〇|ユーザ投稿型，MalwareBazaarと連携|
|[Whois History](http://whoishistory.ru/)|domain||.su,.ruドメイン用whois history|
|[tools.epieos](https://tools.epieos.com/)|mail||メールアドレスで登録しているサービスの調査|
|[searchcode](https://searchcode.com/)|||ソースコードの検索|
|[grep.app](https://grep.app/)|||ソースコードの検索|
|[PublicWWW](https://publicwww.com/)|||ソースコードの検索|

# whois
- ref:
  - [Harvesting Whois Data for OSINT](https://webbreacher.com/2016/08/09/harvesting-whois-data-for-osint-using-viewdns-info/)
### Domain privacy (Whois privacy) 
- ドメインを登録するときに，Registrantの情報(人物・組織名，電話番号，メールアドレス，住所など)をRegistrarが用意した情報に置き換えて公開しプライバシーを保護するサービス
- ref:
    - [The Best Reason for Domain Name Privacy Services](https://giga.law/blog/2019/12/11/best-reason-domain-privacy-services)

# Recon
### VPN
- [ProtonVPN](https://protonvpn.com/)
- [NordVPN](https://nordvpn.com/ja/)
- [PrivateInternetAccess](https://jpn.privateinternetaccess.com/)
- [Mullvad](https://mullvad.net/ja/)
- [AirVPN](https://airvpn.org/)
- [OVPN](https://www.ovpn.com/en)
- ref:
    - [Which VPN Providers Really Take Anonymity Seriously in 2020?](https://torrentfreak.com/best-vpn-anonymous-no-logging/)
    - [Finding The Origin IP Behind CDNs](https://infosecwriteups.com/finding-the-origin-ip-behind-cdns-37cd18d5275)
### Scanner
- [Nmap](https://nmap.org/)
- [Zmap](https://github.com/zmap/zmap)
- [Zgrab](https://github.com/zmap/zgrab2)
    
# Forum/Darkweb
- [DDIR](https://github.com/nenaiko-dareda/DDIR)
    - Darkwebリサーチ向けのオープンソースのデータセット
    - 機械学習による違法サイトの自動検出などに活用できる
    - 4340の.onion sitesをクロールしてデータを収集(41%くらいが違法サイト)
        - 不正な薬物,サイバー攻撃請負,偽のクレカ,児童ポルノ,海賊版販売,犯罪行為(マネロンなど)
    - [\[CODE BLUE 2019\]DDIR: ダークウェブの研究を目的としたオープンソースデータセット\[レポート\]](https://dev.classmethod.jp/articles/code-blue-2019-d1-blue-1550/)
- ref:
    - [User-Friendly Loaders and Crypters Simplify Intrusions and Malware Delivery](https://www.recordedfuture.com/user-friendly-loaders-crypters/)
    - [TRADING IN THE DARK](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/trading-in-the-dark)
    - [HACKER INFRASTRUCTURE AND UNDERGROUND HOSTING 101](https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/hacker-infrastructure-and-underground-hosting-101-where-are-cybercriminal-platforms-offered?utm_source=trendmicroresearch&utm_medium=smk&utm_campaign=0720_HostingInfra)
    - https://www.youtube.com/channel/UCOlAvnPulOZBKnuEfIXM3OA/videos
    - [Memex – DARPA’s search engine for the Dark Web](https://nakedsecurity.sophos.com/2015/02/16/memex-darpas-search-engine-for-the-dark-web/)
        - DARPAが開発しているDarkWeb用検索エンジン「Memex」について
    - https://twitter.com/AlecMuffett/status/989239019472027648
    - [CrimeBoards](https://github.com/misterch0c/CrimeBoards)
        - リスト

# Bulletproof hosting
- 特徴:
    - 物理的な差し押さえなどを回避するために，核シェルター，独立国家などの特殊なデータセンターにサーバが設置されることがある
        - その国の情勢，政治などの変化の影響をうけて，Bulletproof hostingのサービスが提供できなくなることもある
    - 支払いに仮想通貨が利用できる
    - メールやパスワードのみで利用できることもある
    - DMCA（米デジタルミレニアム著作権法）を無視すると明記されると記載されている
    - 会社の住所・実態がない
    - サービス内容の割りには高額
- 利用例：
    - c2サーバ，スパム配信サーバ，海賊版サイト，児童ポルノサイト，Torrentサイト，反政府サイト
- ref:
    - [海賊版サイト問題の解決を阻む「防弾ホスティング」その歴史から現在までを読み解く](https://www.itmedia.co.jp/news/articles/1901/17/news013.html)
    - [Flowspec – TA505’s bulletproof hoster of choice](https://blog.intel471.com/2020/07/15/flowspec-ta505s-bulletproof-hoster-of-choice/)
    - https://weboas.is/media/host.txt
    - [OffshoreVPS - list of VPS providers around the world](http://offshorevps.org/)
    - [VPS hosts that accept Bitcoin](http://cryto.net/~joepie91/bitcoinvps.html)
    - [ASwatch: An AS Reputation System to Expose Bulletproof Hosting ASes@SIGCOM 15](https://cybersecurity.uga.edu/publications/5-6-2_ASwatch_camera.pdf)
    - [Criminal Abuse in RIPE IP space](https://ripe77.ripe.net/presentations/134-RIPE77_Anti_Abuse_WG.pdf)
    - [アンダーグラウンドで提供されるインフラとホスティングサービスの実情](https://blog.trendmicro.co.jp/archives/26252)

# yara source
- https://github.com/advanced-threat-research/Yara-Rules
- [malpedia](https://malpedia.caad.fkie.fraunhofer.de/)
- https://github.com/Yara-Rules/rules
- https://github.com/JPCERTCC/MalConfScan/blob/master/yara/rule.yara
- https://github.com/ctxis/CAPE/tree/master/data/yara/CAPE
- https://github.com/Neo23x0/signature-base/tree/master/yara
- https://github.com/ProIntegritate/Yara-rules
- https://github.com/k-vitali/Malware-Misc-RE
- https://gist.github.com/JohnLaTwC
- https://github.com/InQuest/yara-rules
- https://github.com/InQuest/awesome-yara
- https://github.com/reversinglabs/reversinglabs-yara-rules

## tools
- yara関連(rule生成や検索)のツール
    - [yara-signator](https://github.com/fxb-cocacoding/yara-signator)
    - [yarGen](https://github.com/Neo23x0/yarGen)
    - [YaraGenerator](https://github.com/Xen0ph0n/YaraGenerator)
    - [mquery](https://github.com/CERT-Polska/mquery/)
        - Public Version(http://mquery.net/)
    - [PasteHunter](https://github.com/kevthehermit/PasteHunter)
    - [INQUEST LABS](https://labs.inquest.net/tools/yara/b64-regexp-generator)
    - [VT Code Similarity Yara Generator](https://github.com/arieljt/VTCodeSimilarity-YaraGen)

# IoC source
- https://github.com/StrangerealIntel/CyberThreatIntel
- https://github.com/Neo23x0/sigma
- https://github.com/karttoon/iocs
- https://github.com/stamparm/maltrail/tree/master/trails/static
- https://github.com/malwareinfosec/EKFiddle/blob/master/Regexes/MasterRegexes.txt
- https://gist.github.com/kirk-sayre-work
- http://www.covert.io/threat-intelligence/
- https://gist.github.com/sysgoblin
- https://github.com/eset/malware-ioc
- https://github.com/jstrosch/malware-samples
- https://github.com/threatrack/cti_report_collection

# MindMaps
- https://github.com/sbousseaden/Slides/tree/master/Hunting%20MindMaps
- https://github.com/caschnee/misp-use-cases/blob/master/MISP_use_cases_detailed.png
- https://www.marcolancini.it/2018/blog-hacker-playbook-mindmap/
- https://twitter.com/mark_valenzia/status/1258689477460889600
- https://www.amanhardikar.com/mindmaps/webapptest.html
- https://webbreacher.com/2018/07/12/osint-map/

- https://twitter.com/ReinH/status/1303800051802628096


# Image Search
- [onlineocr](https://www.onlineocr.net/)
    - ocrで画像に含まれる文字を抽出するサイト


# Cheet Sheet
### shodan
- 日付の検索(apiのみ)
```
after:dd/mm/yyyy
before:dd/mm/yyyy
```
- ssl証明書のシリアル番号検索
```
ssl.cert.serial:
```
- ssl証明書のハッシュ値検索(sha1)
```
ssl.cert.fingerprint:
```
- favicon hash(favicon->base64 encode->Murmur hash)の検索
```
http.favicon.hash:
```
- shodan-cliの検索
```
shodan search --fields ip_str '${query}' --limit 1000 | cat 
```
- ref:
    - [SCANdalous!（ネットワークスキャンデータと自動化を用いた外部検知）](https://www.fireeye.jp/blog/jp-threat-research/2020/07/scandalous-external-detection-using-network-scan-data-and-automation.html)
### Censys
- または
```
or
```
- かつ
```
and
```
- 日付の検索
```
updated_at:[yyyy-mm-dd TO yyyy-mm-dd]
updated_at:[yyyy-mm-dd TO *]
```
- ssl証明書のハッシュ値検索(sha256)
```
443.https.tls.certificate.parsed.fingerprint_sha256:
```
-ref
    - https://censys.io/advanced-persistent-infrastructure-tracking/
### ZoomEye
- ssl証明書のシリアル番号検索
```
"Serial Number: "
```
- api:認証(curl)
```
curl -XPOST https://api.zoomeye.org/user/login -d '{"username":"${email}","password":"${password}"}'
```
- api:検索(curl)
```
curl -X GET https://api.zoomeye.org/host/search?query='"${query}"&page=1' -H "Authorization: JWT ${tokenid}"
```

-ref:
    - [利用 ZoomEye 追踪多种 Redteam C&C 后渗透攻击框架](https://paper.seebug.org/1301/)
    - https://www.zoomeye.org/searchResult?q=%22CobaltStrike%20Beacon%20configurations%22
### Fofa
- または
```
&&
```
- かつ
```
||
```
- 日付の検索
```
after="yyyy/mm/dd"
before="yyyy/mm/dd"
```
- ssl証明書のシリアル番号検索
```
cert:""
```
- プロトコル検索
```
protocol=="cobaltstrike"
```
### Twitter
- 期間の指定(JST)
```
since:2020/05/28_00:00:00_JST until:2020/05/28_23:59:59_JST
```
- 特定ユーザからツイート，特定ユーザへのツイートを除外
```
-from:@hoge -to:@huga
```

### VirusTotal
- [File search modifiers](https://support.virustotal.com/hc/en-us/articles/360001385897-Search-modifiers)
- コードブロックを共有するサンプルのリストを取得
```
code-similar-to:[hash]
```
- 類似したファイルアイコンやテンプレート(doc等)を検索
```
main_icon_dhash:[hash]
```
### Others
- osintとか関係なく
- [Web-Attack-Cheat-Sheet](https://github.com/riramar/Web-Attack-Cheat-Sheet)
- [The Ultimate List of SANS Cheat Sheet](https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets/)
- [XSS without HTML: Client-Side Template Injection with AngularJS](https://portswigger.net/research/xss-without-html-client-side-template-injection-with-angularjs)
- [matplotlib](https://github.com/matplotlib/cheatsheets)
- [Lateral Movement DetectionGPO Settings Cheat Sheet](https://compass-security.com%/fileadmin%2FDatein%2FResearch%2FWhite_Papers%2Flateral_movement_detection_basic_gpo_settings_v1.0.pdf)

# TLP
- 機密情報を確実に適切な組織または人に共有するために使われる一連の標示
- メールに適用する場合は，件名と本文にTLPの色情報(大文字)を記載
- 文書などに適用する場合は，各ページのヘッダー，フッターにTLPの色情報を記載する(右側推奨)
- TLPの色情報は大文字かつ12ポイント以上で記載する必要がある
- TLP:RED
    - 公開不可，関係者限り
    - 会議や会話に実際に参加した人のみ
- TLP:AMBER
    - 限定公開，関係者が所属する組織内で共有可能
    - 所属組織内，クライアント，顧客等
    - 範囲は情報公開者が指定できる
- TLP:GREEN
    - 限定公開，コミュニティ内で共有可能
    - 所属組織内，所属コミュニティ内，パートナー組織等
- TLP:WHITE
    - 制限なく共有可能
- ref:
    - [TRAFFIC LIGHT PROTOCOL (TLP)](https://www.jpcert.or.jp/research/FIRST-TLP.html)


# lxAK
    - https://twitter.com/onlineosint/status/1378433784501112836/photo/1
    - https://twitter.com/ADITYASHENDE17/status/1338361960455270403

# HUMINT
    - [Cyber Intelligence HUMINT Operations](https://bank-security.medium.com/cyber-intelligence-humint-operations-2d3d526e4007) 

# ref:
- [OSINT Cheat-Sheat,2019](https://inteltechniques.com/JE/OSINT_Packet_2019.pdf)
- [Download OSINT Bookmarks@OSINT Combine](https://www.osintcombine.com/osint-bookmarks)
    - OSINTに有用なWebサイトをまとめたBookmarkを提供
- [普段の調査で利用するOSINTまとめ,qiita,2020-03](https://qiita.com/00001B1A/items/4d8ceb53993d3217307e)
- ["Must Have" Free Resources for Open-Source Intelligence (OSINT)](https://www.sans.org/blog/-must-have-free-resoulrces-for-open-source-intelligence-osint-/)
- [脅威インテリジェンスの教科書](https://www.slideshare.net/tomohisaishikawa/ss-236323562)
- [すぐ貢献できる！偽サイトの探索から通報まで](https://qiita.com/v_avenger/items/2eeef2d69c85eb1570e8)
- https://blog.bushidotoken.net/2020/09/fantastic-apts-and-where-to-find-them.html
- https://jsac.jpcert.or.jp/archive/2020/pdf/JSAC2020_4_ogawa-niseki_jp.pdf
- [Analyzing Network Infrastructure as Composite Objects](https://www.domaintools.com/resources/blog/analyzing-network-infrastructure-as-composite-objects)
- [Week in OSINT](https://sector035.nl/articles/category:week-in-osint)
- [STATE OSINT](https://stateofosint.com/)
- [List of Resource Links from Open-Source Intelligence Summit 2021](https://www.sans.org/blog/list-of-resource-links-from-open-source-intelligence-summit-2021/)
- [SANS OSINT Summit@Youtube](https://www.youtube.com/hashtag/osintsummit)
