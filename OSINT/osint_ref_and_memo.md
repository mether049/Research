# OSINT Tools
### OS/VM

|OS/VM|remarks|
|:-|:-|
|[Buscador OSINT VM](https://inteltechniques.com/buscador/)|IntelTechniques提供<br>Buscador(ブスカドル，スペイン語：先駆者・開拓者)<br>多くのOSINTツールが実装されたOSINT用のVM|
|[whonix](https://www.whonix.org/)|インターネットTorを経由only<br>[Kicksecure](https://www.whonix.org/wiki/Kicksecure)<br>キーストローク匿名化<br>AnboxによるAndroidアプリケーションの実行|
|[Tails](https://tails.boum.org/)|インターネットTorを経由only<br>USBやDVDからの起動を前提|
|[Qubes OS](https://www.qubes-os.org/)|Xenを利用して全てのアプリケーションを独立して実行<br>Template VMにwhonixを利用することができ，より匿名性を高めることが可<br>Template VMは複数のOS(Windows,Fedora,Whonix,Debian,etc.)を同時に利用することが可|

- [Maltego](https://www.paterva.com/downloads.php)
- [FinalRecon](https://github.com/thewhiteh4t/FinalRecon)
- [Recon-ng](https://github.com/lanmaster53/recon-ng)
- [OWASP Maryam](https://github.com/saeeddhqan/Maryam)
- [Photon](https://github.com/s0md3v/Photon)
- [Maryam](https://github.com/saeeddhqan/Maryam)
- [URLhaus monitor](https://github.com/ninoseki/urlhaus_monitor)
- [DDIR](https://github.com/nenaiko-dareda/DDIR)
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
- site name,input,API,remarks,site URL

|name|input|API|remarks|site|
|:-|:-|:-|:-|:-|
|urlscan.io|url,ip,domain,hash,ASN|〇||https://urlscan.io/|
|RiskIQ|domain,ip,url,hash,email,certificates|〇||https://www.riskiq.com/products/community-edition/|
|IBM X-Force Exchange|domain,url,IP,md5,hash tag,cve,application name|〇||https://exchange.xforce.ibmcloud.com/|
|VirusTotal|url,hash,IP|〇||https://www.virustotal.com/gui/home/upload|
|Censys|ip,domain,url,certificates|〇||https://censys.io/|
|SHODAN||〇||https://www.shodan.io/ip|
|Alien Vault|domain,url,ip,hash,email,yara,cve,mutex,etc.|〇||https://otx.alienvault.com/|
|PhishTank|url|〇|https://www.phishtank.com/index.php|
|ANYRUN|domain,ip,url,hash,MITRE ATT&CK technique ID,Suricata ID||online sandbox|https://app.any.run/submissions|
|URLhaus|domain,ip,url,hash|||https://urlhaus.abuse.ch/browse/|
|Web Insight|url|||http://webint.io/|url||
|ThreatMiner|domain,ip,url,hash,email,ssl,UA,apt name,malware family,registry,mutex,etc.|||https://www.threatminer.org/index.php|
|Threats Crowd|domain,ip,url,email,organization|||powered byAlienVault|https://www.threatcrowd.org/|
|MX TOOLBOX|ip,domain|||https://mxtoolbox.com/blacklists.aspx|
|pastebin|keyword|||https://pastebin.com/|
|HYBRID ANALYSIS|domain,ip,url,hash,yara,string||online sandbox|https://www.hybrid-analysis.com/|
|cape sandbox|domain,ip,url,hash,command,malware family,registry,mutex,string||online sandbox|https://cape.contextis.com/analysis/search/|
|JOESandbox Cloud|domain,ip,hash,hash tag||online sandbox|https://www.joesandbox.com/#advanced|
|Vulmon|cve,company,product|||https://vulmon.com/|
|IntelligenceX|domain,ip,url,email,bitcoin address,etc.|||https://intelx.io/|
|NerdyData|||https://www.bellingcat.com/resources/how-tos/2015/07/23/unveiling-hidden-connections-with-google-analytics-ids/|https://nerdydata.com/|
|SpyOnWeb|domain,ip,url|||http://spyonweb.com/|
|aguse|url,email|||https://www.aguse.jp/|
|DomainBigData|domain,ip,url,registrant name,email|||https://domainbigdata.com/|
|DN pedia|domain|||https://dnpedia.com/tlds/search.php|
|Robtex|domain,ip,url,as number|||https://www.robtex.com/|
|nccgroupnumber|domain||researching typosquatting|https://labs.nccgroup.trust/typofinder/|
|VX Vault|ip,url,hash|||http://vxvault.net/ViriList.php|
|VMRAY ANALYZER||||https://www.vmray.com/analyzer-malware-sandbox-free-trial/?utm_campaign=reports&utm_source=vmray&utm_medium=analysis2&utm_content=report|
|malwareurl|domain,ip,url|||https://www.malwareurl.com/listing-urls.php|
|dedoLa||||http://dedola.eu/malware.php|
|SPLOITUS|cve,applicationname||researching poc|https://sploitus.com/|
|Feodo Tracker|ip|||https://feodotracker.abuse.ch/browse/|
|MalShare|hash,yara|||https://malshare.com/|
|ZoomyEye|domain,ip,country,etc.|||https://www.zoomeye.org/|
|FOFA|domain,ip,country,etc.|||https://fofa.so/|
|ONYPHE|domain,country,etc.||||https://www.onyphe.io/|
|PublicWWW|domain,ip,keyword,code snippet,tld,etc.|||https://publicwww.com/|
|Twitter IOC Hunter|domain,ip,url,hash,email,user,hash tag|||http://tweettioc.com/search|
|Wayback Machine|url||archive|https://archive.org/web/|
|Stanford Web Archive Portal|url||archive|https://swap.stanford.edu/|
|UK Parliament Web Archive|url||archive|http://webarchive.parliament.uk/|
|Library of Congress|url||archive|https://www.loc.gov/|
|totalhash|domain,ip,hash,urll,UA,email,mutex,registry|||https://totalhash.cymru.com/search/|
|IP & Domain Reputation Center|domain,ip,hash|||https://talosintelligence.com/reputation_center|
|GREYNOISE||〇|検索機能が豊富<br>malicious判定された機器のみの検索等が可能|https://viz.greynoise.io/|

# ref:
- [OSINT Cheat-Sheat,2019](https://inteltechniques.com/JE/OSINT_Packet_2019.pdf)
