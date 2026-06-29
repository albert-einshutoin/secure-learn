#!/usr/bin/env node

const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const outDir = path.join(root, 'docs', 'scenario-guides');
const assetDir = path.join(outDir, 'assets');

// Scenario pages are generated from one data source so curriculum changes do
// not leave stale HTML, navigation, or readiness scoring behind.
const benchmarks = [
  {
    label: 'OWASP Web Security Testing Guide',
    href: 'https://owasp.org/www-project-web-security-testing-guide/',
    use: 'Web/API攻撃を「再現、証跡、修正確認」へ落とす基準',
  },
  {
    label: 'OWASP API Security Top 10 2023',
    href: 'https://owasp.org/API-Security/editions/2023/en/0x11-t10/',
    use: 'BOLA、認証、認可、resource consumption、injectionの抜け漏れ確認',
  },
  {
    label: 'Google SRE: Service Level Objectives',
    href: 'https://sre.google/sre-book/service-level-objectives/',
    use: 'availability、latency、error budgetをシナリオ証跡に接続',
  },
  {
    label: 'Google SRE Workbook: Incident Response',
    href: 'https://sre.google/workbook/incident-response/',
    use: 'severity、incident command、timeline、postmortemの評価軸',
  },
  {
    label: 'Kubernetes Security Concepts',
    href: 'https://kubernetes.io/docs/concepts/security/',
    use: 'container、cluster、network、secret、policyの本番運用観点',
  },
  {
    label: 'Kubernetes Network Policies',
    href: 'https://kubernetes.io/docs/concepts/services-networking/network-policies/',
    use: 'NetworkPolicyによるeast-west通信制御の確認',
  },
];

const globalGaps = [
  'API Securityの上位領域はS28で、IDOR/BOLA、SSRF、unsafe upload、RCE、business logic abuseとして扱う。',
  'SRE/Observabilityの上位領域はS24-S25で、burn-rate alert、metrics/logs/traces、high-cardinality、alert fatigueとして扱う。',
  'Backend/Distributed/Performanceの上位領域はS26-S27/S32で、idempotency、migration/rollback、transaction、pagination、query planとして扱う。',
  'Cloud/IaC/Supply Chain/Releaseの上位領域はS22-S23/S29/S33で、IAM、KMS、OPA、SBOM、signing、canary、advisoryとして扱う。',
];

const scenarios = [
  {
    id: 'S1',
    slug: 's1-portscan',
    title: 'ポートスキャン',
    layer: 'L3/L4',
    level: '初級',
    roles: ['Whitehat', 'SRE'],
    score: 3,
    summary: 'nmapで露出ポートを列挙し、Suricata/Kibanaで偵察を検知する基礎シナリオ。',
    objective: '許可されたDockerネットワーク内でactive scanningを実行し、検知、攻撃元特定、誤検知判断、遮断判断までを説明できるようにする。',
    flow: [
      ['Prepare', 'docker compose up -dで環境を起動し、Kaliコンテナへ入る。'],
      ['Execute', '/scripts/s1_portscan.sh または nmapのSYN/FIN/XMAS/NULL scanを実行する。'],
      ['Observe', 'Suricata fast.log/eve.jsonとKibana DiscoverでSCANアラートを確認する。'],
      ['Decide', '社内スキャン、監視、攻撃のどれかをsource.ipと時刻で分類する。'],
      ['Improve', 'thresholdや許可済みscannerの扱いを変更し、検知漏れと誤検知の両方を説明する。'],
    ],
    commands: [
      'docker compose up -d',
      'docker exec -it soc-lab-kali /bin/bash',
      '/scripts/s1_portscan.sh',
      'docker exec soc-lab-suricata grep SCAN /var/log/suricata/fast.log | tail -20',
      "docker exec soc-lab-suricata jq 'select(.alert)' /var/log/suricata/eve.json | head",
    ],
    tools: [
      ['nmap', 'SYN/connect/FIN/XMAS/NULL scanを比較し、L3/L4の見え方を学ぶ。'],
      ['Suricata', 'SCAN signature、source.ip、destination portを確認する。'],
      ['Kibana', 'event.module:suricata AND rule.name:*SCAN* で時系列化する。'],
      ['Fail2ban', '必要時だけ遮断。scan検知とauth BANを混同しない。'],
    ],
    evidence: [
      'scan開始時刻、終了時刻、対象IP、実行コマンド',
      'Suricata fast.log/eve.jsonの該当行',
      'Kibana検索条件とスクリーンショット',
      '遮断する/しない判断と理由',
    ],
    worldClass: [
      '承認済みscannerと攻撃者scanを区別するallowlist/threshold設計を追加する。',
      '検知ルール変更をPR化し、before/afterの検知率と誤検知率を比較する。',
      '資産台帳や変更管理と照合する運用判断を課題に加える。',
    ],
  },
  {
    id: 'S2',
    slug: 's2-bruteforce',
    title: 'APIブルートフォース',
    layer: 'L7',
    level: '初級',
    roles: ['Whitehat', 'Backend', 'SRE'],
    score: 4,
    summary: 'Hydraとアプリログを使い、認証攻撃、lockout、Fail2ban、SIEM相関を確認する。',
    objective: '認証失敗のログ、アプリ側lockout、Fail2ban BAN、正常ユーザー影響を一つの時系列で説明する。',
    flow: [
      ['Prepare', 'docker compose up -d --buildで最新版アプリを起動する。'],
      ['Execute', '/scripts/s2_bruteforce.shで低リスクな認証試行を行う。'],
      ['Observe', 'auth.log、Fail2ban status、Kibana Timelineを確認する。'],
      ['Backend check', 'AuthServiceのlockout unit testとtoken検証を確認する。'],
      ['SRE check', 'BAN中も/healthと/health/readyがSLO内か確認する。'],
    ],
    commands: [
      'docker compose up -d --build',
      'docker exec -it soc-lab-kali /bin/bash',
      '/scripts/s2_bruteforce.sh',
      'docker exec soc-lab-app tail -20 /var/log/app/auth.log',
      'docker exec soc-lab-fail2ban fail2ban-client status nestjs-auth',
      'npm --prefix app test -- --test-name-pattern auth',
    ],
    tools: [
      ['Hydra', '認証試行を自動化する。対象は必ずラボ内に限定する。'],
      ['NestJS auth.log', 'login_failed/login_successをsource.ipとuser.nameで見る。'],
      ['Fail2ban', 'BAN有無、jail、bantime、findtime、maxretryを確認する。'],
      ['Node test', 'lockout、token署名、credential material非露出を回帰テスト化する。'],
    ],
    evidence: [
      'auth.logの失敗回数とsource.ip',
      'Fail2banのBAN状態',
      '正常ログインがcredential materialを返さない証跡',
      'lockout発動条件と誤検知時のunban手順',
    ],
    worldClass: [
      'credential stuffing検知として、同一credentialの横展開やlow-and-slow attackを追加する。',
      'MFA、risk-based authentication、rate limitのshared store化を設計課題にする。',
      'アカウントロックがDoS化しないよう、解除・通知・support flowを追加する。',
    ],
  },
  {
    id: 'S3',
    slug: 's3-sqli',
    title: 'SQLインジェクション',
    layer: 'L7',
    level: '中級',
    roles: ['Whitehat', 'Backend'],
    score: 4,
    summary: 'sqlmap/curlでSQLiを試行し、アプリが400で拒否し、DB queryがparameterizedであることを証明する。',
    objective: '攻撃の再現、検知、修正済み契約、DB integration testを一つのremediation evidenceにまとめる。',
    flow: [
      ['Prepare', 'docker compose up -d --buildでPostgreSQL込みの環境を起動する。'],
      ['Attack', '/scripts/s3_sqli.shでpayloadとsqlmapを実行する。'],
      ['Defense', 'HTTP 400、sqli_attempt log、Suricata SQLI alertを確認する。'],
      ['Backend proof', 'UsersServiceのparameterized query testとDB integration testを実行する。'],
      ['Report', 'CWE-89、影響、修正、残リスク、再発防止をPR形式で記録する。'],
    ],
    commands: [
      'docker compose up -d --build',
      'docker exec -it soc-lab-kali /bin/bash',
      '/scripts/s3_sqli.sh',
      'scripts/backend_hands_on_tests.sh',
      'npm --prefix app test',
      'npm --prefix app run test:integration',
    ],
    tools: [
      ['sqlmap', '脆弱性探索ツールとして使うが、修正済みでは成立しないことを確認する。'],
      ['curl', '単一payloadのHTTP statusとresponse shapeを確認する。'],
      ['PostgreSQL integration test', '実DBに対してpayloadがデータを返さないことを検証する。'],
      ['Suricata/Kibana', '攻撃試行そのものの検知証跡を保存する。'],
    ],
    evidence: [
      'SQLi payloadとHTTP 400結果',
      'UsersService unit testとDB integration test結果',
      'Suricata/App logの検知証跡',
      'エラーにSQL/stack traceが出ていない証跡',
    ],
    worldClass: [
      'boolean/time/error/union/in-band/out-of-bandの観点でpayload coverageを増やす。',
      'ORM/Repository境界、migration、transaction rollbackまで拡張する。',
      'DASTをCIの安全なプロファイルで走らせ、誤検知triageを課題化する。',
    ],
  },
  {
    id: 'S4',
    slug: 's4-dos',
    title: 'DoS攻撃',
    layer: 'L7/SRE',
    level: '初級',
    roles: ['SRE', 'Whitehat', 'Backend'],
    score: 3,
    summary: '安全なリクエスト量でL7負荷をかけ、rate limit、latency、availability、BAN判断を確認する。',
    objective: '攻撃検知とSLO劣化を分け、availabilityとp95 latencyを根拠にincident severityを判断する。',
    flow: [
      ['Baseline', 'scripts/sre_smoke.shとscripts/load_hands_on_tests.shで攻撃前のSLOを測る。'],
      ['Execute', '/scripts/s4_dos.shで安全な負荷をかける。'],
      ['Observe', 'access.log、Suricata、Fail2ban、/healthを同時に見る。'],
      ['Decide', 'rate limit、BAN、capacity増強、rollbackのどれを選ぶか判断する。'],
      ['Recover', '負荷停止後のSLO回復とMTTRを記録する。'],
    ],
    commands: [
      'scripts/sre_smoke.sh',
      'REQUESTS=100 CONCURRENCY=10 scripts/load_hands_on_tests.sh',
      'docker exec -it soc-lab-kali /bin/bash',
      '/scripts/s4_dos.sh',
      'docker exec soc-lab-app tail -30 /var/log/app/access.log',
    ],
    tools: [
      ['curl/ab-like shell loop', '安全な範囲でリクエスト量を作る。'],
      ['express-rate-limit', '429 contractと正当ユーザー影響を確認する。'],
      ['SRE smoke/load scripts', 'latencyとfailureを定量化する。'],
      ['Kibana', 'error rate、status code、source.ipを時系列化する。'],
    ],
    evidence: [
      '攻撃前後のp95 latency、failure count',
      '429/5xxの比率',
      'rate limitまたはBANの発動有無',
      '顧客影響とseverity判断',
    ],
    worldClass: [
      'burn-rate alertとerror budget消費を追加する。',
      'queueing、timeout、circuit breaker、autoscalingの比較課題を入れる。',
      '負荷テスト結果からcapacity planning reportを作る。',
    ],
  },
  {
    id: 'S5',
    slug: 's5-file-tamper',
    title: '重要ファイル改変',
    layer: 'OS',
    level: '中級',
    roles: ['Whitehat', 'SRE'],
    score: 3,
    summary: 'Auditdで重要ファイル変更を記録し、変更者、時刻、対象、復旧判断を追う。',
    objective: 'Docker外のホスト監査として、FIM、監査ログ、復旧、postmortemまで扱えるようにする。',
    flow: [
      ['Prepare', 'Linux hostでauditdを有効化し、audit.rulesを読み込む。'],
      ['Execute', '安全なtest fileまたは明示許可された重要ファイル操作を行う。'],
      ['Observe', 'ausearch/aureportでPATH/SYSCALL/auidを確認する。'],
      ['Assess', '変更が正当作業か不正操作かを判断する。'],
      ['Recover', '差分、バックアップ、immutable/FIM戦略を記録する。'],
    ],
    commands: [
      'sudo cp auditd/audit.rules /etc/audit/rules.d/soc-lab.rules',
      'sudo systemctl restart auditd',
      'docker exec -it soc-lab-kali /bin/bash',
      '/scripts/s5_file_tamper.sh',
      'sudo ausearch -k passwd_changes -i | head -50',
      'sudo aureport --file --summary',
    ],
    tools: [
      ['auditd', 'SYSCALL/PATH/auidでOS操作を記録する。'],
      ['ausearch', '検知キー、ファイル、時刻で絞り込む。'],
      ['aureport', '監査イベントをレポート化する。'],
      ['Kibana/Filebeat', 'ホスト監査ログをSIEMへ流す設計を確認する。'],
    ],
    evidence: [
      '変更ファイル、auid、実行コマンド',
      '変更前後の差分または復元根拠',
      '正当/不正の判断',
      'FIMやbackup/restoreの改善案',
    ],
    worldClass: [
      'AIDE/TripwireやeBPF系FIMとの比較を追加する。',
      'backup restore drillとRTO/RPO測定を追加する。',
      'Linux以外のKubernetes node/host監査へ展開する。',
    ],
  },
  {
    id: 'S6',
    slug: 's6-privesc',
    title: '権限昇格',
    layer: 'OS',
    level: '中級',
    roles: ['Whitehat', 'SRE'],
    score: 3,
    summary: 'sudo/su/SUID探索をAuditdで記録し、最小権限と異常昇格の判断を学ぶ。',
    objective: '権限昇格を実行できたで終わらせず、許可、証跡、影響、封じ込め、権限設計まで説明する。',
    flow: [
      ['Prepare', 'auditdとprivilege escalation rulesを有効化する。'],
      ['Execute', 'sudo、su、SUID列挙を安全な範囲で実行する。'],
      ['Observe', 'audit.logとauth.logでeuid=0、auid、commandを確認する。'],
      ['Decide', '正当運用、要調査、不正昇格に分類する。'],
      ['Improve', 'sudoers最小化、MFA、session recordingを提案する。'],
    ],
    commands: [
      'sudo auditctl -l | grep privilege',
      'sudo whoami',
      'find / -perm -4000 2>/dev/null | head',
      'sudo ausearch -k privilege_escalation -i | head -50',
      'sudo aureport --auth --summary',
    ],
    tools: [
      ['sudo/su', '昇格イベントを意図的に発生させる。'],
      ['find', 'SUID/SGIDの攻撃面を列挙する。'],
      ['Auditd', 'euid、auid、execveを保存する。'],
      ['sudoers review', 'NOPASSWDや広すぎる権限を評価する。'],
    ],
    evidence: [
      '昇格前後のuid/euid',
      'auditdのexecve証跡',
      '正当性判断とowner確認',
      'sudoers改善案とrollback手順',
    ],
    worldClass: [
      'GTFOBins調査、container breakout防止、Linux capabilityを追加する。',
      'PAM/MFA/session recordingの運用設計を追加する。',
      'Kubernetes RBAC/PodSecurityと接続する。',
    ],
  },
  {
    id: 'S7',
    slug: 's7-lateral',
    title: '横断インシデント',
    layer: '全体',
    level: '上級',
    roles: ['Whitehat', 'SRE', 'Backend'],
    score: 4,
    summary: '偵察、認証攻撃、SQLi試行、ファイル/権限イベントを一つのattack chainとして相関する。',
    objective: '複数レイヤーの検知をtimeline化し、MTTD/MTTR、影響範囲、改善PRまでまとめる。',
    flow: [
      ['Start', '/scripts/s7_lateral.shで段階的な攻撃チェーンを実行する。'],
      ['Correlate', 'source.ip、timestamp、event.actionでSuricata/App/Fail2ban/Auditdを繋ぐ。'],
      ['Contain', 'BANやサービス保護の判断を記録する。'],
      ['Eradicate', '成立した攻撃があるか、修正済みで拒否されたかを分ける。'],
      ['Improve', '検知ルール、backend test、runbookをPRとして提案する。'],
    ],
    commands: [
      'docker compose up -d --build',
      'docker exec -it soc-lab-kali /bin/bash',
      '/scripts/s7_lateral.sh',
      'docker exec soc-lab-fail2ban fail2ban-client status',
      'scripts/incident_drill.sh',
    ],
    tools: [
      ['Kibana Timeline', '複数ログソースを時系列でまとめる。'],
      ['Suricata', 'scan、SQLI、DOSのネットワーク側証跡を見る。'],
      ['Fail2ban', '封じ込めアクションの発生時刻を見る。'],
      ['Postmortem template', '検知、対応、恒久対策を第三者に伝える。'],
    ],
    evidence: [
      'attack chainの開始/検知/対応時刻',
      '各phaseのログソースとKQL',
      '成功した攻撃と拒否された攻撃の区別',
      '改善PRのテストとrollback方針',
    ],
    worldClass: [
      'MITRE ATT&CK navigator風のcoverage mapを追加する。',
      'purple team形式で検知漏れをissue化する。',
      'realistic incident rolesとcommunication drillを追加する。',
    ],
  },
  {
    id: 'S8',
    slug: 's8-arp',
    title: 'L2 ARP観測',
    layer: 'L2',
    level: '初級',
    roles: ['Whitehat', 'SRE'],
    score: 2,
    summary: 'Docker bridge上のARP/neighbor cacheを観測し、L2の限界と証跡不足を説明する。',
    objective: 'ARP spoofingは行わず、観測だけでL2事象がL3/L4到達性に与える影響を理解する。',
    flow: [
      ['Prepare', 'Docker ComposeでKaliとtargetを同一bridge上に置く。'],
      ['Observe', 'ip neigh、arping、tcpdumpでneighbor cacheを確認する。'],
      ['Explain', 'Docker環境で見えるL2と見えない物理switch側証跡を分ける。'],
      ['Risk', 'ARP spoofingを第三者環境で実施してはいけない理由を説明する。'],
      ['Design', 'DHCP snooping、DAI、NAC、switch logの運用設計を考える。'],
    ],
    commands: [
      'docker compose up -d',
      'docker exec -it soc-lab-kali /bin/bash',
      '/scripts/s8_l2_arp_observe.sh',
      'ip neigh show',
      'arping -c 3 app',
    ],
    tools: [
      ['ip neigh', 'neighbor cacheのIP/MAC対応を見る。'],
      ['arping', 'ARP replyの有無を確認する。'],
      ['tcpdump', '必要時にARP/ICMPフレームを観測する。'],
      ['Suricata flow', 'Docker環境では補助証跡として扱う。'],
    ],
    evidence: [
      'neighbor cacheのbefore/after',
      'ARP replyの出力',
      'L2で見えない証跡の説明',
      '実運用で取得すべきswitch/NAC証跡',
    ],
    worldClass: [
      '物理/仮想network機器のログ収集設計を追加する。',
      'ARP spoofingではなく防御設定の検証へ広げる。',
      'ゼロトラスト/セグメンテーションと接続する。',
    ],
  },
  {
    id: 'S9',
    slug: 's9-icmp',
    title: 'L3 ICMP到達性・偵察',
    layer: 'L3',
    level: '初級',
    roles: ['Whitehat', 'SRE'],
    score: 3,
    summary: 'ping/tracerouteで到達性を確認し、ネットワーク障害とアプリ障害を切り分ける。',
    objective: 'ICMPを偵察と運用監視の両面から評価し、遮断前に必要な監視要件を整理する。',
    flow: [
      ['Baseline', '正常時のping、traceroute、/healthを取得する。'],
      ['Execute', '/scripts/s9_l3_icmp_recon.shで到達性確認を実行する。'],
      ['Observe', 'Suricata L3 ICMP alertとKibana searchを確認する。'],
      ['Triage', 'ICMP不通、TCP通、HTTP不調などの切り分け表を作る。'],
      ['Improve', '監視通信と攻撃偵察を分ける閾値を設計する。'],
    ],
    commands: [
      'docker exec -it soc-lab-kali /bin/bash',
      '/scripts/s9_l3_icmp_recon.sh',
      'ping -c 3 app',
      'traceroute app',
      'curl -fsS http://localhost:3000/health',
    ],
    tools: [
      ['ping', '到達性と往復時間を見る。'],
      ['traceroute', '経路とhopの変化を見る。'],
      ['Suricata', 'ICMP/host discoveryの検知を見る。'],
      ['SRE smoke', 'L3正常でもL7が正常とは限らないことを確認する。'],
    ],
    evidence: [
      'ICMP結果とHTTP health結果',
      'Suricata alert',
      '不通原因の仮説',
      '監視通信の許可/遮断方針',
    ],
    worldClass: [
      'network SLIを設計し、blackbox monitoringと接続する。',
      'ICMP遮断環境の代替probeを追加する。',
      'Kubernetes Service/NetworkPolicyの到達性drillを追加する。',
    ],
  },
  {
    id: 'S10',
    slug: 's10-tcp-state',
    title: 'L4 TCP状態・フラグ異常',
    layer: 'L4',
    level: '中級',
    roles: ['Whitehat', 'SRE'],
    score: 3,
    summary: 'SYN/connect/FIN/NULL/XMAS scanの違いを観測し、L4状態と検知ルールを理解する。',
    objective: 'TCP flagとconnection stateを説明し、露出ポート最小化と検知閾値の設計に繋げる。',
    flow: [
      ['Prepare', 'Kaliからtargetへ到達できる状態を確認する。'],
      ['Execute', '/scripts/s10_l4_tcp_state.shで複数scanを実行する。'],
      ['Observe', 'nmap結果、Suricata fast.log、app access.logを比較する。'],
      ['Triage', 'L4で止まった通信とL7まで届いた通信を区別する。'],
      ['Improve', '露出ポート、firewall、IDS thresholdを見直す。'],
    ],
    commands: [
      'docker exec -it soc-lab-kali /bin/bash',
      '/scripts/s10_l4_tcp_state.sh',
      'nmap -sS -p 3000 app',
      'nmap -sF -sN -sX -p 3000 app',
      'docker exec soc-lab-suricata tail -30 /var/log/suricata/fast.log',
    ],
    tools: [
      ['nmap', 'scan方式ごとの応答差を見る。'],
      ['Suricata', 'TCP flag anomalyやscan alertを見る。'],
      ['App access.log', 'connect scanがL7まで到達したか確認する。'],
      ['Firewall/NetworkPolicy', 'L4で制限すべき通信を設計する。'],
    ],
    evidence: [
      'scan方式ごとのnmap結果',
      'Suricata alertとtimestamp',
      'L7到達有無',
      '露出ポート削減案',
    ],
    worldClass: [
      'normal baselineとの差分検知を追加する。',
      'Kubernetes NetworkPolicyやcloud security groupの実証へ広げる。',
      'service mesh/proxyのL4 timeout設計を比較する。',
    ],
  },
  {
    id: 'S11',
    slug: 's11-session-stress',
    title: 'L5セッション圧迫',
    layer: 'L5',
    level: '中級',
    roles: ['SRE', 'Backend'],
    score: 3,
    summary: '不完全HTTP sessionを保持し、timeout、connection limit、SLO影響を観測する。',
    objective: '大量攻撃ではなく少数接続のリソース消費を理解し、proxy/app/IDSの責務分担を説明する。',
    flow: [
      ['Baseline', '/healthとload gateで正常時latencyを測る。'],
      ['Execute', '/scripts/s11_l5_session_stress.shで不完全sessionを作る。'],
      ['Observe', '接続保持時間、Suricata alert、/health latencyを見る。'],
      ['Triage', 'timeout、keepalive、rate limit、connection limitを分けて説明する。'],
      ['Improve', 'reverse proxyやapp serverのtimeout設計を提案する。'],
    ],
    commands: [
      'scripts/sre_smoke.sh',
      'docker exec -it soc-lab-kali /bin/bash',
      '/scripts/s11_l5_session_stress.sh',
      'scripts/load_hands_on_tests.sh',
      'docker exec soc-lab-suricata tail -30 /var/log/suricata/fast.log',
    ],
    tools: [
      ['nc', '不完全なHTTP sessionを保持する。'],
      ['Suricata', 'session pressure/DOS系alertを確認する。'],
      ['SRE smoke/load', 'latencyとavailabilityを定量化する。'],
      ['Proxy config', 'header timeout、keepalive、max connectionsを設計する。'],
    ],
    evidence: [
      '接続保持数と保持時間',
      '攻撃中のlatency/failure',
      'timeout設定案',
      '正常ユーザー影響の判断',
    ],
    worldClass: [
      'slowloris系の安全な再現とproxy防御を追加する。',
      'event loop lagやconnection pool exhaustionをmetrics化する。',
      '負荷と攻撃を区別するalert設計を追加する。',
    ],
  },
  {
    id: 'S12',
    slug: 's12-tls-boundary',
    title: 'L6 TLS可視性境界',
    layer: 'L6',
    level: '中級',
    roles: ['Whitehat', 'SRE', 'Backend'],
    score: 2,
    summary: 'TLS ClientHelloをHTTP serviceへ送り、暗号化境界とIDS可視性の制約を理解する。',
    objective: 'TLS終端前後で見える情報、見えない情報、監査すべきログを説明できるようにする。',
    flow: [
      ['Execute', '/scripts/s12_l6_tls_boundary.shを実行する。'],
      ['Observe', 'openssl s_clientとcurl -vkの失敗理由を読む。'],
      ['Explain', 'TLS終端前にIDSが見られるSNI/証明書/flowと、見られないHTTP bodyを分ける。'],
      ['Design', 'reverse proxyでTLS終端する場合のaccess log、cert expiry、WAF位置を決める。'],
      ['Operate', '証明書期限とTLS設定を監視対象に加える。'],
    ],
    commands: [
      'docker exec -it soc-lab-kali /bin/bash',
      '/scripts/s12_l6_tls_boundary.sh',
      'openssl s_client -connect app:3000 -servername app',
      'curl -vk https://localhost:3000/health',
    ],
    tools: [
      ['openssl s_client', 'handshakeと証明書情報を確認する。'],
      ['curl -vk', 'HTTPS/TLS failureをHTTP layerと分けて見る。'],
      ['Suricata', 'TLS metadataが見える範囲を確認する。'],
      ['Reverse proxy', 'TLS終端とWAF/IDSの責務分担を設計する。'],
    ],
    evidence: [
      'TLS handshake failureの出力',
      '可視性境界の説明',
      '本番相当のTLS termination案',
      '証明書期限監視案',
    ],
    worldClass: [
      'nginx/EnvoyなどのTLS終端を実装してmTLS、HSTS、cipher policyを扱う。',
      'certificate expiry alertとrenewal drillを追加する。',
      '暗号化通信検査の法務/プライバシー判断を課題化する。',
    ],
  },
  {
    id: 'S13',
    slug: 's13-dns',
    title: 'L7 DNS観測',
    layer: 'L7',
    level: '初級',
    roles: ['Whitehat', 'SRE'],
    score: 2,
    summary: 'Docker embedded DNSのservice discoveryを観測し、内部偵察と運用依存を理解する。',
    objective: 'DNSが単なる名前解決ではなく、偵察、障害、service discoveryの証跡になることを理解する。',
    flow: [
      ['Observe', 'getent hosts、dig、/etc/resolv.confでDocker DNSを見る。'],
      ['Map', 'service名、IP、networkを図にする。'],
      ['Explain', 'Docker embedded DNSがどこで動き、Suricataで安定観測しづらい理由を説明する。'],
      ['Detect', '異常なservice discoveryをSIEMで見つける設計を考える。'],
      ['Operate', 'DNS障害時の切り分け手順を作る。'],
    ],
    commands: [
      'docker exec -it soc-lab-kali /bin/bash',
      '/scripts/s13_l7_dns_observe.sh',
      'getent hosts app db elasticsearch',
      'cat /etc/resolv.conf',
      'dig app',
    ],
    tools: [
      ['getent/dig', '名前解決の実結果を確認する。'],
      ['Docker DNS', '127.0.0.11とservice discoveryを理解する。'],
      ['Kibana', '実運用ではDNS logをSIEM化する前提で検索設計する。'],
      ['Network map', 'service nameとIPの対応を可視化する。'],
    ],
    evidence: [
      'service名とIPの対応',
      'resolver設定',
      'DNSログがない場合の証跡不足説明',
      '実運用で取るべきDNS telemetry',
    ],
    worldClass: [
      'CoreDNS log、DNS tunneling、DGA検知を追加する。',
      'Kubernetes Service DNSとNetworkPolicyを接続する。',
      'DNS failureをincident drill化する。',
    ],
  },
  {
    id: 'S14',
    slug: 's14-sre-incident',
    title: 'SREインシデント対応',
    layer: '横断/SRE',
    level: '上級',
    roles: ['SRE', 'Backend', 'Whitehat'],
    score: 4,
    summary: '攻撃やDB停止をSLO/incident responseへ接続し、MTTD/MTTRとpostmortemを作る。',
    objective: 'セキュリティイベントをサービス影響へ翻訳し、severity、暫定対応、恒久対応を判断する。',
    flow: [
      ['Baseline', 'scripts/sre_smoke.shとload gateで正常時SLOを記録する。'],
      ['Inject', 'DoSまたはRUN_CHAOS=1 scripts/incident_drill.shで障害を注入する。'],
      ['Detect', '/health/ready、Suricata、Fail2ban、Kibanaを同時に見る。'],
      ['Respond', 'severity、incident commander、customer impact、rollback判断を記録する。'],
      ['Learn', 'postmortemで再発防止とownerを明記する。'],
    ],
    commands: [
      'scripts/sre_smoke.sh',
      'REQUESTS=100 CONCURRENCY=10 scripts/load_hands_on_tests.sh',
      'RUN_CHAOS=1 scripts/incident_drill.sh',
      'docker compose ps',
      'docker exec soc-lab-fail2ban fail2ban-client status',
    ],
    tools: [
      ['SRE smoke/load scripts', 'availabilityとp95 latencyを測る。'],
      ['readiness probe', '依存関係障害を/healthと分離する。'],
      ['Kibana', 'alertとuser impactを相関する。'],
      ['Postmortem template', 'timeline、impact、action itemを残す。'],
    ],
    evidence: [
      'SLO baselineと障害中の差分',
      'MTTD/MTTR',
      'severityと顧客影響',
      'postmortem action item',
    ],
    worldClass: [
      'burn-rate multi-window alertを実装する。',
      'canary/rollback/release freeze判断をdrill化する。',
      'traces/metrics/logsの相関とdashboardを追加する。',
    ],
  },
  {
    id: 'S15',
    slug: 's15-capstone',
    title: 'ホワイトハット/SRE修了課題',
    layer: '全体',
    level: '上級',
    roles: ['Whitehat', 'SRE', 'Backend'],
    score: 4,
    summary: 'S1-S14を組み合わせ、攻撃、検知、修正、運用、報告を一つの成果物にする。',
    objective: '単発実行ではなく、第三者が再現できるevidence portfolioを作り、PR品質で改善を説明する。',
    flow: [
      ['Plan', 'S8-S13から2つ、S2-S6から2つ、S14を選ぶ。'],
      ['Run', '各シナリオのHTMLに従い、開始/検知/対応時刻を記録する。'],
      ['Correlate', 'Kibana、logs、scripts reportsを一つのtimelineにまとめる。'],
      ['Improve', '1つ以上の検知/運用/backend改善をPR形式で説明する。'],
      ['Review', '安全性、再現性、検知、対応、改善、報告の全項目でセルフレビューする。'],
    ],
    commands: [
      'docker compose up -d --build',
      'scripts/lab_quality_gate.sh',
      'RUN_CHAOS=1 scripts/incident_drill.sh',
      'cp docs/templates/incident-report.md reports/my-incident-report.md',
      'cp docs/templates/vulnerability-remediation-pr.md reports/my-remediation-pr.md',
    ],
    tools: [
      ['All attack scripts', '選択したscenarioを安全に実行する。'],
      ['Quality gate', 'backend/security/opsの回帰を確認する。'],
      ['Templates', 'incident、remediation、postmortemを成果物化する。'],
      ['GitHub PR', '改善をreview可能な単位で提出する。'],
    ],
    evidence: [
      '選択シナリオと実行ログ',
      'timeline、MTTD、MTTR',
      '検知ルールまたはアプリ/運用改善案',
      'セルフレビューと残リスク',
    ],
    worldClass: [
      'CVSS/CWE、MITRE、SLO、rollbackを一つのexecutive summaryへ統合する。',
      'peer reviewを前提に、反証可能な証跡だけで主張を組み立てる。',
      '次のissue backlogを優先度付きで作る。',
    ],
  },
];

const advancedScenarios = [
  {
    id: 'S16',
    slug: 's16-linux-internals-isolation',
    title: 'Linux Internals・隔離境界',
    layer: 'OS/Kernel',
    level: '上級',
    roles: ['SRE', 'Whitehat'],
    score: 4,
    summary: 'systemd、cgroups、namespaces、seccomp、capabilitiesを、containerの障害調査と防御境界として扱う。',
    concept: 'Linux internalsは、プロセスがCPU、メモリ、ファイル、ネットワーク、syscall、権限をどう使っているかを読む訓練です。抽象的には、障害や侵害を「OS資源と隔離境界の変化」として説明します。',
    examples: [
      'cgroupsでCPU/memory制限があると、アプリは5xxではなくlatency悪化やOOMとして壊れる。',
      'namespace内のrootはhost rootではないが、capabilityが広いと危険なsyscallやnetwork操作が可能になる。',
      'strace/lsof/ssで、HTTP requestがsocket、file descriptor、syscall待ちとして見える。',
    ],
    objective: 'Linuxの資源管理と隔離機構を、container security、障害調査、SRE runbookに接続できるようにする。',
    flow: [
      ['Observe', 'ps、ss、lsof、straceでappと通信の状態を見る。'],
      ['Inspect', 'docker inspectでcap_drop、security_opt、read_only、resource設定を確認する。'],
      ['Explain', 'namespace、cgroup、capability、seccompが守る範囲と守れない範囲を表にする。'],
      ['Tune safely', 'kernel tuning値は変更せず、見るべき値と変更時のrollback条件を整理する。'],
      ['Report', 'OS起因障害とアプリ起因障害を分けた調査メモを作る。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p10',
      'docker exec learn-toolbox ss -tan',
      "docker exec learn-toolbox sh -lc 'curl -fsS http://app:3000/health && lsof -iTCP -P -n | head'",
      "docker inspect soc-lab-app | jq '.[0].HostConfig.CapDrop, .[0].HostConfig.SecurityOpt'",
      'scripts/world_class_hands_on_check.sh linux',
    ],
    tools: [
      ['ss/lsof', 'socketとfile descriptorからresource exhaustionを切り分ける。'],
      ['strace', 'syscall境界で詰まりを観測する。'],
      ['docker inspect', 'capability、security_opt、mount、resource制限を見る。'],
      ['cgroups/namespaces', 'container隔離の実体として説明する。'],
    ],
    evidence: [
      'process、socket、fd、syscallを対応付けた記録',
      'capabilities/seccomp/cgroupの防御境界説明',
      'kernel tuning候補とrollback条件',
      'OS起因とアプリ起因の切り分け表',
    ],
    worldClass: [
      'eBPF/perf flamegraphを本番相当環境で扱う。',
      'seccomp profileとcapability最小化をCIで検査する。',
      'kernel CVE時のnode drain、upgrade、rollback runbookを作る。',
    ],
  },
  {
    id: 'S17',
    slug: 's17-ebpf-perf-forensics',
    title: 'eBPF・perf・低レイヤー可観測性',
    layer: 'Kernel/Observability',
    level: '上級',
    roles: ['SRE', 'Whitehat'],
    score: 3,
    summary: 'eBPF、perf、flamegraph、syscall telemetryを、性能調査と侵害調査の共通言語として整理する。',
    concept: 'eBPF/perfは、アプリログに出ないCPU、syscall、network、file accessを低オーバーヘッドで見るための方法です。抽象的には、ユーザー空間から見えない挙動を安全に観測する技術です。',
    examples: [
      'CPU高騰時、HTTP handlerではなくcrypto、JSON parse、DB client待ちのどこが熱いかを見る。',
      '怪しいprocessがどのfileやnetworkへ触れたかをevent streamとして記録する。',
      '本番ではroot権限とprivacy影響があるため、取得範囲と保存期間を決める。',
    ],
    objective: 'perf/eBPFを無闇に実行するのではなく、観測したい質問、権限、コスト、プライバシーを定義できるようにする。',
    flow: [
      ['Question', 'CPU、syscall、network、file accessのどれを見たいか決める。'],
      ['Local proxy', 'ラボではstrace、ss、lsofで代替観測する。'],
      ['Design', '本番でeBPFを使う場合の権限、範囲、retentionを設計する。'],
      ['Correlate', '低レイヤーeventをrequest_idやincident timelineへ繋ぐ。'],
      ['Control', '観測ツール自体の負荷と機密情報露出を評価する。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p10',
      "docker exec learn-toolbox sh -lc 'ss -tan && lsof -iTCP -P -n | head'",
      'scripts/world_class_hands_on_check.sh linux',
      'sed -n "1,220p" docs/templates/incident-report.md',
    ],
    tools: [
      ['perf', 'CPU sampleとflamegraphでhot pathを見る。'],
      ['eBPF', 'syscall、network、file eventを低オーバーヘッドで観測する。'],
      ['strace', 'ラボでsyscall観測を安全に代替する。'],
      ['Incident timeline', 'kernel/userland eventを時系列に繋ぐ。'],
    ],
    evidence: [
      '観測したい質問と選んだtoolの理由',
      '低レイヤーeventとアプリ/SLOの対応',
      '権限、負荷、privacyのリスク評価',
      '本番導入時のrollbackと停止条件',
    ],
    worldClass: [
      'BCC/bpftrace/Cilium Tetragonなどで実イベントを取得する。',
      'flamegraphをPRの性能証跡として扱う。',
      'EDR telemetryとSRE telemetryの重複/責務を整理する。',
    ],
  },
  {
    id: 'S18',
    slug: 's18-tcp-backlog-loadbalancer',
    title: 'TCP再送・SYN backlog・Load Balancer',
    layer: 'L4/L7 Edge',
    level: '上級',
    roles: ['SRE', 'Whitehat'],
    score: 4,
    summary: 'TCP再送、SYN backlog、conntrack、L4/L7 load balancer logを、SLO劣化の根拠として扱う。',
    concept: 'TCPやload balancerの障害は、アプリログに到達しないことがあります。抽象的には、requestがアプリに届く前にどこで落ちたかを観測点ごとに切り分けます。',
    examples: [
      'SYN backlogが溢れるとアプリにはrequestが来ず、clientはtimeoutや再送を見る。',
      'L7 LBはHTTP statusを出せるが、L4 LBはconnection resetやtimeoutの証跡が中心になる。',
      'conntrack枯渇はpodやappではなくnode/network層のcapacity問題になる。',
    ],
    objective: 'L4/L7の観測点を整理し、アプリ障害、LB障害、network capacityを分けてincident判断できるようにする。',
    flow: [
      ['Baseline', 'app直通とedge proxy経由のhealth latencyを測る。'],
      ['Observe', 'ss、tcpdump、nginx access log、app access logを比較する。'],
      ['Model', 'SYN backlog、conntrack、timeoutのfailure modeを図にする。'],
      ['Decide', 'scale out、rate limit、LB timeout変更、rollbackの条件を決める。'],
      ['Report', 'どの観測点に証跡があり、どこにないかを明記する。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p11',
      'curl -fsS http://localhost:8080/health',
      'docker exec learn-toolbox ss -tan',
      'scripts/load_hands_on_tests.sh',
      'scripts/world_class_hands_on_check.sh network',
    ],
    tools: [
      ['ss/tcpdump', 'connection state、再送、reset、timeoutの手がかりを見る。'],
      ['Nginx edge proxy', 'L7 proxyのaccess/error logを観測点にする。'],
      ['SRE load scripts', 'p95/p99とfailure countを定量化する。'],
      ['Runbook', 'LB/app/networkの切り分け順を固定する。'],
    ],
    evidence: [
      'direct/proxyのlatency差分',
      'connection stateとHTTP logの対応',
      'SYN backlog/conntrack/LB timeoutの説明',
      'capacityまたはrollback判断',
    ],
    worldClass: [
      'real LB/NLB/ALB/Envoy logsを取り込む。',
      'packet lossとretransmissionをblackbox SLIへ接続する。',
      'load balancer config変更をcanary化する。',
    ],
  },
  {
    id: 'S19',
    slug: 's19-mtls-cert-rotation',
    title: 'TLS/mTLS・証明書ローテーション',
    layer: 'L6/Security',
    level: '上級',
    roles: ['SRE', 'Backend', 'Whitehat'],
    score: 4,
    summary: 'TLS handshake、mTLS、証明書期限、cipher policy、rotationをreleaseとincidentの両面で扱う。',
    concept: 'TLS/mTLSは暗号化だけでなく、identity、trust、期限、失効、互換性を運用する仕組みです。抽象的には、通信相手をどう信頼し、その信頼をどう更新するかを扱います。',
    examples: [
      '証明書期限切れはアプリdeployなしで全リクエストを止める。',
      'mTLSではclient証明書の発行、失効、rotationがauthorization境界になる。',
      'cipher policy更新は古いclientを切る可能性があるため互換性証跡が必要になる。',
    ],
    objective: 'TLS/mTLS failureをHTTP障害と分け、rotation、expiry alert、trust boundaryを設計できるようにする。',
    flow: [
      ['Probe', 'openssl s_clientでhandshake情報または失敗理由を見る。'],
      ['Boundary', 'TLS終端前後でIDS/WAF/appが見える情報を分ける。'],
      ['Design', 'mTLSのCA、client cert、rotation、revocationを設計する。'],
      ['Alert', 'expiry、handshake error、protocol downgradeを監視項目にする。'],
      ['Release', '証明書更新のcanaryとrollbackを決める。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p11',
      'docker exec learn-toolbox openssl s_client -connect app:3000 -servername app </dev/null || true',
      'docker exec learn-toolbox openssl version',
      'scripts/world_class_hands_on_check.sh network',
      'sed -n "1,220p" docs/scenario-guides/s12-tls-boundary.html',
    ],
    tools: [
      ['openssl s_client', 'handshake、SNI、証明書、protocolを確認する。'],
      ['Nginx/Envoy', 'TLS終端、mTLS、cipher policyの実装候補にする。'],
      ['Prometheus alert', 'cert expiryとhandshake errorを監視する。'],
      ['Release checklist', 'rotationとrollbackを運用手順にする。'],
    ],
    evidence: [
      'TLS/mTLS trust boundary図',
      '証明書期限とrotation手順',
      'handshake failureの切り分け表',
      '互換性とrollback判断',
    ],
    worldClass: [
      '実TLS終端とmTLS labを追加する。',
      'SPIFFE/SPIREやservice mesh identityへ拡張する。',
      '証明書失効とemergency rotation drillを実施する。',
    ],
  },
  {
    id: 'S20',
    slug: 's20-quic-bgp-cdn-edge',
    title: 'QUIC/HTTP3・BGP/Anycast・CDN Edge',
    layer: 'Internet Edge',
    level: '上級',
    roles: ['SRE', 'Whitehat'],
    score: 3,
    summary: 'QUIC/HTTP3、BGP、Anycast、CDN routingを、直接操作せずに設計・観測・障害対応として学ぶ。',
    concept: 'Internet edgeは自分のサーバだけで完結しません。抽象的には、clientがどのedgeに到達し、どのprotocolでoriginへ流れ、どの証跡で問題を切り分けるかを扱います。',
    examples: [
      'Anycast障害では一部地域だけが別edgeへ吸われ、全体監視では見逃すことがある。',
      'QUICはUDPなので、TCP前提のmiddleboxやpacket capture設計では見え方が変わる。',
      'CDN cache purgeやorigin shield変更は、securityとavailabilityの両方に影響する。',
    ],
    objective: 'BGP/Anycast/CDNを危険に操作せず、観測点、ログ、rollback、vendor escalationの設計をできるようにする。',
    flow: [
      ['Map', 'client、DNS、CDN edge、origin、LB、appの経路図を作る。'],
      ['Protocol', 'TCP/HTTP2とUDP/QUICで観測点が変わることを整理する。'],
      ['Failure', '地域限定、resolver限定、cache限定の障害パターンを作る。'],
      ['Evidence', 'edge log、origin log、DNS log、synthetic probeの必要性を書く。'],
      ['Escalate', 'vendorへ渡すべきtimestamp、colo、ray id相当、traceを定義する。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p11',
      'docker exec learn-toolbox sh -lc "dig localhost || true; curl -I http://app:3000/health"',
      'scripts/world_class_hands_on_check.sh edge',
      'sed -n "1,220p" docs/scenario-guides/s20-quic-bgp-cdn-edge.html',
    ],
    tools: [
      ['dig/curl', 'DNSとHTTPの基本観測を行う。'],
      ['CDN logs', '実運用ではedge colo、cache status、request idを見る。'],
      ['Synthetic probe', '地域/ISP差分を監視する。'],
      ['Runbook', 'BGP/CDN vendor escalationに必要な証跡を定義する。'],
    ],
    evidence: [
      'edge routing経路図',
      'QUIC/HTTP3とTCP/HTTP2の観測差分',
      'CDN/BGP障害時の必要ログ一覧',
      'vendor escalation template',
    ],
    worldClass: [
      '実CDN sandboxでcache rule、WAF、origin fallbackを検証する。',
      'multi-region synthetic monitoringを追加する。',
      'BGP leak/route hijackをtabletop exercise化する。',
    ],
  },
  {
    id: 'S21',
    slug: 's21-kubernetes-platform',
    title: 'Kubernetes本番運用・Platform Guardrails',
    layer: 'Kubernetes',
    level: '上級',
    roles: ['SRE', 'Whitehat', 'Backend'],
    score: 4,
    summary: 'Helm、Kustomize、Operator/CRD、Admission、RBAC、NetworkPolicy、PodSecurity、HPA/VPA、upgradeを本番運用として扱う。',
    concept: 'Kubernetes本番運用はyaml適用ではなく、危険な変更を入れない仕組み、壊れても戻せる仕組み、upgradeしても契約を守る仕組みを作ることです。',
    examples: [
      'Admissionでprivileged podやlatest imageを拒否する。',
      'RBACでsecretを読めるServiceAccountを限定し、NetworkPolicyでeast-west通信を絞る。',
      'CRD/Operator upgrade前にAPI deprecationとrollback条件を確認する。',
    ],
    objective: 'Kubernetesをdeployment targetではなく、policyとoperabilityを持つplatformとして説明できるようにする。',
    flow: [
      ['Read', 'k8s/baseのDeployment、Service、HPA、NetworkPolicy、StatefulSetを読む。'],
      ['Validate', 'scripts/k8s_static_check.shで最低限のguardrailを検査する。'],
      ['Design', 'Helm/Kustomize/Admission/RBAC/PodSecurityの追加設計を書く。'],
      ['Operate', 'cluster upgrade、multi-cluster、service meshのrisk tableを作る。'],
      ['Review', 'manifest diff reviewで拒否すべき変更を列挙する。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p12',
      'scripts/k8s_static_check.sh',
      'find k8s/base -type f -maxdepth 2 -print',
      'sed -n "1,220p" docs/runbooks/kubernetes-operations.md',
      'scripts/world_class_hands_on_check.sh kubernetes',
    ],
    tools: [
      ['Kustomize/Helm', '環境差分とrelease unitを管理する。'],
      ['Admission Controller', 'policy違反をclusterへ入る前に拒否する。'],
      ['RBAC/NetworkPolicy/PodSecurity', 'identity、network、runtimeの境界を作る。'],
      ['HPA/VPA', 'capacityとresource requestを運用する。'],
    ],
    evidence: [
      'manifestごとの安全条件説明',
      'Admission/RBAC/NetworkPolicyの設計案',
      'upgradeとrollback手順',
      'service mesh/multi-cluster導入時のリスク評価',
    ],
    worldClass: [
      'kind/minikubeでAdmission policyを実行する。',
      'OPA Gatekeeper/KyvernoをCIとclusterに入れる。',
      'service mesh mTLSとtraffic shiftingを実測する。',
    ],
  },
  {
    id: 'S22',
    slug: 's22-cloud-iam-audit',
    title: 'Cloud IAM/KMS/VPC/Audit Logs',
    layer: 'Cloud Security',
    level: '上級',
    roles: ['Whitehat', 'SRE'],
    score: 4,
    summary: 'AWS/GCP/Azure共通のIAM、KMS、VPC、Security Group、Audit Logs、Org policyを設計レビューする。',
    concept: 'Cloud securityはサービス名の暗記ではなく、誰が、どのnetworkから、どのkeyで、何を変更し、その証跡が残るかを制御することです。',
    examples: [
      'IAM wildcardを見つけ、action/resource/conditionに分解する。',
      'KMS keyのrotation、owner、break-glass、deletion protectionを定義する。',
      'CloudTrail/Audit Logsから変更者、source IP、対象resourceをtimeline化する。',
    ],
    objective: 'cloud accountを実際に触らず、設計レビューとincident evidenceの観点を安全に身につける。',
    flow: [
      ['Review', 'サンプルIAM/Audit logを見て危険な権限と不足ログを指摘する。'],
      ['Network', 'public/private subnet、security group、private endpointを図にする。'],
      ['Key', 'KMS/secret rotationとbreak-glassの手順を書く。'],
      ['Govern', 'Org policy/SCPで禁止すべき操作を定義する。'],
      ['Report', 'cloud incident timelineをincident reportへ転記する。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p13',
      'scripts/world_class_hands_on_check.sh cloud',
      'sed -n "1,220p" docs/scenario-guides/s22-cloud-iam-audit.html',
      'sed -n "1,220p" docs/templates/incident-report.md',
    ],
    tools: [
      ['IAM policy review', 'wildcard、condition不足、cross-account trustを見る。'],
      ['KMS/Secrets Manager', 'key owner、rotation、auditを設計する。'],
      ['CloudTrail/Audit Logs', '変更証跡をincident timelineへ変換する。'],
      ['VPC/Security Group', 'private networkingとegress制御を設計する。'],
    ],
    evidence: [
      'IAM/KMS/VPC/Auditの設計レビュー',
      '過剰権限とpublic exposureの指摘',
      'Org policy/SCP案',
      'secret rotationとbreak-glass手順',
    ],
    worldClass: [
      '実sandbox cloud accountでread-only auditを行う。',
      'CloudTrail/Audit LogsをSIEMへ取り込む。',
      'multi-account landing zoneのguardrailを実装する。',
    ],
  },
  {
    id: 'S23',
    slug: 's23-terraform-policy-drift',
    title: 'Terraform・Drift Detection・OPA',
    layer: 'IaC',
    level: '上級',
    roles: ['SRE', 'Whitehat'],
    score: 4,
    summary: 'Terraform module、state、drift、OPA/Conftest、CI plan reviewを、infra変更の安全装置として扱う。',
    concept: 'IaCは環境構築の自動化だけではなく、変更意図、差分、policy違反、driftをレビュー可能にする仕組みです。',
    examples: [
      '0.0.0.0/0 ingressやpublic bucketをpolicyで拒否する。',
      'prod/stageのstateを分け、module inputだけで差分を表現する。',
      'console手変更をdriftとして検出し、緊急対応後にcodeへ戻す。',
    ],
    objective: 'IaC変更をplan、policy、state、drift、rollbackの5点でレビューできるようにする。',
    flow: [
      ['Read', 'Terraform風サンプルを読み、危険なdiffを指摘する。'],
      ['Policy', 'OPA/Conftest相当の禁止条件を文章化する。'],
      ['CI', 'plan outputにsecurity reviewerが何をコメントするかを書く。'],
      ['Drift', '手変更を検出した時の復旧方針を決める。'],
      ['Promote', 'dev/stage/prodの環境分離と承認を設計する。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p14',
      'scripts/world_class_hands_on_check.sh iac',
      'sed -n "1,220p" docs/scenario-guides/s23-terraform-policy-drift.html',
      'sed -n "1,220p" docs/templates/vulnerability-remediation-pr.md',
    ],
    tools: [
      ['Terraform plan', 'resource差分、destroy、public exposureを見る。'],
      ['OPA/Conftest', '組織policyをCIで機械的に評価する。'],
      ['State backend', 'locking、encryption、environment separationを確認する。'],
      ['Drift detection', '手変更とcode差分を検出する。'],
    ],
    evidence: [
      'plan review comment',
      'policy-as-code禁止条件',
      'state/drift/environment分離の説明',
      '例外承認と期限',
    ],
    worldClass: [
      'terraform plan JSONとOPA/Regoを実行する。',
      'drift detectionをscheduled CIへ入れる。',
      'cloud asset inventoryとIaC stateを照合する。',
    ],
  },
  {
    id: 'S24',
    slug: 's24-burn-rate-observability',
    title: 'Burn-rate Alert・RED/USE・Alert Fatigue',
    layer: 'Observability/SRE',
    level: '上級',
    roles: ['SRE', 'Backend'],
    score: 4,
    summary: 'SLI/SLO、error budget、multi-window burn-rate、RED/USE metrics、alert fatigueを実測結果へ接続する。',
    concept: 'Observabilityはdashboardを増やすことではなく、顧客影響を判断する質問に答えられる信号を作ることです。',
    examples: [
      '5分burn-rateが高いが1時間では低い場合、pageではなくticketにする。',
      'RED metricsでAPI影響を、USE metricsでnode/resource飽和を分ける。',
      'user_idをmetric labelに入れるとhigh cardinalityで監視基盤を壊す。',
    ],
    objective: 'SLO違反を検知し、alertの緊急度、owner、actionを判断できるようにする。',
    flow: [
      ['Baseline', 'load testでp95とerror rateを取得する。'],
      ['Budget', 'SLOとerror budget消費を計算する。'],
      ['Alert', 'multi-window burn-rateのpage条件とticket条件を決める。'],
      ['Correlate', 'log、metric、traceをどの質問に使うか整理する。'],
      ['Reduce noise', 'alert fatigueを減らすdedup、silence、routingを設計する。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p15',
      'REQUESTS=120 CONCURRENCY=8 scripts/load_hands_on_tests.sh',
      'curl -fsS http://localhost:9090/-/ready',
      'scripts/world_class_hands_on_check.sh observability',
    ],
    tools: [
      ['Prometheus', 'SLIとburn-rateをquery化する。'],
      ['Grafana', 'incident中の判断画面を作る。'],
      ['OpenTelemetry', 'trace/log/metric correlationを設計する。'],
      ['SLO report', 'error budget消費をpostmortemへ残す。'],
    ],
    evidence: [
      'SLI/SLO/error budget計算',
      'burn-rate alert条件',
      'RED/USE metrics設計',
      'alert fatigue削減方針',
    ],
    worldClass: [
      'PromQLでmulti-window burn-rate alertを実装する。',
      'trace_id/request_idを全ログへ通す。',
      'high-cardinality guardrailをCIで検査する。',
    ],
  },
  {
    id: 'S25',
    slug: 's25-otel-trace-log-correlation',
    title: 'OpenTelemetry・Trace/Log Correlation',
    layer: 'Observability',
    level: '上級',
    roles: ['SRE', 'Backend'],
    score: 3,
    summary: 'OpenTelemetry、tracing、log correlation、high-cardinality対策をbackendとSREの共通設計にする。',
    concept: 'Trace/log correlationは、障害時に「遅いrequestがどの依存で詰まったか」を追うための設計です。抽象的には、分散した証跡を一つの因果関係へ戻します。',
    examples: [
      'request_idがapp log、proxy log、DB logにあれば1リクエストの旅を追える。',
      'span attributeにuser_idを無制限に入れるとコストとcardinalityが爆発する。',
      'sampling率は障害調査能力とコストのトレードオフになる。',
    ],
    objective: 'trace、metric、logの責務を分け、相関ID、sampling、cardinality、retentionを設計できるようにする。',
    flow: [
      ['Start', 'otel collector profileを起動する。'],
      ['Design', 'request_id/trace_idをどこで生成し、どこへ伝播するかを書く。'],
      ['Control', 'cardinalityが高い属性と低い属性を分類する。'],
      ['Cost', 'samplingとretentionの方針を決める。'],
      ['Incident', 'slow request調査の手順をrunbook化する。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p15',
      'curl -fsS http://localhost:4318/ || true',
      'scripts/world_class_hands_on_check.sh observability',
      'sed -n "1,160p" learning/otel/otel-collector.yml',
    ],
    tools: [
      ['OpenTelemetry Collector', 'trace/metric/logを受けてexportする中継点。'],
      ['trace_id/request_id', 'ログとtraceを結ぶキー。'],
      ['Sampling', 'コストと調査能力を調整する。'],
      ['Cardinality review', 'label/attribute爆発を防ぐ。'],
    ],
    evidence: [
      'trace/log correlation設計',
      'samplingとretentionの方針',
      'high-cardinality禁止例',
      'slow request runbook',
    ],
    worldClass: [
      'アプリにOTel SDKを実装し、spanを実送信する。',
      'logs/metrics/tracesを同じincident IDで相関する。',
      'observability cost budgetを運用する。',
    ],
  },
  {
    id: 'S26',
    slug: 's26-queue-idempotency-backpressure',
    title: 'Queue・Idempotency・Backpressure',
    layer: 'Distributed Systems',
    level: '上級',
    roles: ['Backend', 'SRE'],
    score: 4,
    summary: 'Kafka/PubSub/Temporal相当の非同期処理を、retry、backoff、idempotency、backpressureとして設計する。',
    concept: '分散システムでは「1回送れば1回処理される」と仮定できません。抽象的には、重複、遅延、順序入れ替わり、部分失敗を前提に契約を作ります。',
    examples: [
      'producer retryで同じmessageが2回届いても、idempotency keyで二重登録を防ぐ。',
      'consumerが遅い時にqueue backlogを見てscale、shed、degradeを判断する。',
      'Temporal workflowではactivity retryとcompensationを明示する。',
    ],
    objective: 'queue/cache依存のfailure modeをAPI契約、SLO、運用runbookへ落とせるようにする。',
    flow: [
      ['Start', 'Redis profileを起動し、queueの代替としてlist/backlogを扱う。'],
      ['Retry', '同じ処理を複数回送る時のidempotency条件を書く。'],
      ['Backpressure', 'backlog増加時の429、degrade、scale判断を作る。'],
      ['Consistency', 'leader election、replication、shardingの選択理由を書く。'],
      ['Report', 'partial failure前提のrunbookを作る。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p16',
      'docker exec learn-toolbox redis-cli -h learning-redis PING',
      'docker exec learn-toolbox redis-cli -h learning-redis LPUSH lab-queue job-1 job-1',
      'docker exec learn-toolbox redis-cli -h learning-redis LLEN lab-queue',
      'scripts/world_class_hands_on_check.sh distributed',
    ],
    tools: [
      ['Redis list', 'queue/backlogの最小モデルとして使う。'],
      ['Kafka/PubSub', '実運用でのpartition、consumer lag、ackを設計する。'],
      ['Temporal', 'workflow、retry、compensationを設計する。'],
      ['Idempotency key', '重複処理を安全にするAPI契約。'],
    ],
    evidence: [
      'retry/backoff/idempotency設計',
      'backlog時のSLO影響と判断',
      'leader election/consistency/shardingの選択理由',
      'partial failure runbook',
    ],
    worldClass: [
      'Kafka/Redpanda profileを追加してconsumer lagを実測する。',
      'Temporal workflowでcompensationを実装する。',
      'chaos testでbroker停止とrecoveryを測る。',
    ],
  },
  {
    id: 'S27',
    slug: 's27-backend-migration-contract',
    title: 'Schema Migration・API Compatibility',
    layer: 'Backend Production',
    level: '上級',
    roles: ['Backend', 'SRE'],
    score: 4,
    summary: 'schema migration/rollback、transaction、race condition、pagination、API versioning、OpenAPI compatibilityを扱う。',
    concept: 'Backend productionは、APIが動くことではなく、変更しても既存clientとデータを壊さないことです。抽象的には、互換性と復旧可能性を設計します。',
    examples: [
      'column renameはadd new column、dual write、backfill、read switch、drop oldの順に分ける。',
      'paginationなしの一覧APIは負荷と情報漏洩の両方の問題になる。',
      'API versioningではold clientが残る期間とdeprecation policyを決める。',
    ],
    objective: 'DB/API変更をmigration、contract、transaction、performance、rollbackの観点でreviewできるようにする。',
    flow: [
      ['Test', 'unit/integration/OpenAPI contractを実行する。'],
      ['Design', 'expand/contract migrationとrollback手順を書く。'],
      ['Concurrency', 'race conditionとtransaction境界のred testを設計する。'],
      ['Scale', 'pagination、index、query plan、connection poolの確認項目を作る。'],
      ['Compat', 'API versioningとdeprecation noticeを設計する。'],
    ],
    commands: [
      'npm --prefix app test',
      'npm --prefix app run test:integration',
      'scripts/backend_hands_on_tests.sh',
      'scripts/world_class_hands_on_check.sh backend',
      'sed -n "1,220p" docs/api/openapi.yaml',
    ],
    tools: [
      ['OpenAPI contract', 'breaking changeを検出する。'],
      ['DB integration test', '実DB境界の安全性を確認する。'],
      ['Migration checklist', 'expand/contractとrollbackを確認する。'],
      ['Load test', 'p95/p99とquery bottleneckを推測する。'],
    ],
    evidence: [
      'migration/rollback plan',
      'contract compatibility test',
      'race condition test案',
      'pagination/index/query plan review',
    ],
    worldClass: [
      '実migration toolを導入しrollback drillを行う。',
      'contract testをconsumer-drivenにする。',
      'query plan regressionをCIで検査する。',
    ],
  },
  {
    id: 'S28',
    slug: 's28-api-business-logic-abuse',
    title: 'BOLA/SSRF/Unsafe Upload/RCE',
    layer: 'API Security',
    level: '上級',
    roles: ['Whitehat', 'Backend'],
    score: 4,
    summary: 'IDOR/BOLA、SSRF、unsafe upload、RCE、business logic abuseを安全なred test設計として扱う。',
    concept: 'API securityの上位リスクは、単純な文字列payloadではなく、認可境界、外部通信、ファイル処理、状態遷移の設計ミスとして現れます。',
    examples: [
      'BOLA: guestが他人のresource idを指定して読めないことを確認する。',
      'SSRF: metadata IPやinternal hostへserver-side fetchできないようallowlistを使う。',
      'unsafe upload/RCE: extension、MIME、content、保存先、実行権限を分けて防ぐ。',
    ],
    objective: '危険な攻撃を外部へ向けず、閉域ラボ内でred test、修正方針、検知方針へ落とす。',
    flow: [
      ['Model', 'resource owner、actor、action、state transitionを表にする。'],
      ['Red test', 'BOLA/SSRF/upload/RCEの失敗すべきケースを書く。'],
      ['Control', 'authorization、egress allowlist、file validation、sandboxを設計する。'],
      ['Detect', '異常なresource access、egress、upload、process spawnの検知を考える。'],
      ['Report', 'CWE/CVSSと再発防止テストをPR化する。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p18',
      'scripts/backend_hands_on_tests.sh',
      'scripts/world_class_hands_on_check.sh api-security',
      'sed -n "1,220p" docs/curriculum/owasp-api-security-track.md',
    ],
    tools: [
      ['OWASP API Top 10', 'BOLA、auth、resource consumption、SSRFをcoverage mapにする。'],
      ['OpenAPI', 'undocumented endpointとbreaking changeを見つける。'],
      ['Backend tests', '認可と入力検証の回帰を固定する。'],
      ['SIEM', '異常なresource/egress/upload/process eventを検知する。'],
    ],
    evidence: [
      'BOLA/SSRF/upload/RCE red test設計',
      '認可/egress/file/sandbox制御案',
      'CWE/CVSSと影響評価',
      '再発防止テストと検知案',
    ],
    worldClass: [
      '実endpointを追加し、red-green-refactorで修正する。',
      'DASTを安全profileでCI実行する。',
      'business logic abuseをstate machine testにする。',
    ],
  },
  {
    id: 'S29',
    slug: 's29-supply-chain-release',
    title: 'Supply Chain・SBOM・Secure Release',
    layer: 'Secure SDLC',
    level: '上級',
    roles: ['Whitehat', 'Backend', 'SRE'],
    score: 4,
    summary: 'SBOM、SAST、DAST、SCA、secret scanning、artifact signing、provenance、release noteをrelease gateへ統合する。',
    concept: 'Supply chain securityは、コードだけでなく依存、CI、artifact、署名、配布、脆弱性開示までを攻撃面として扱います。',
    examples: [
      'SCAは依存CVE、SASTはコードpattern、DASTは実行中API、SBOMは部品表を担当する。',
      'artifact signingで、mainのどのcommitからimageが作られたか検証可能にする。',
      'secret scanningで漏洩を早期検知し、rotationまでを手順化する。',
    ],
    objective: 'secure releaseをCI結果、SBOM、scan、署名、rollback、advisoryの証跡で説明できるようにする。',
    flow: [
      ['Inventory', 'package-lockとDocker imageからcomponent inventoryを作る。'],
      ['Scan', 'npm audit、secret scanning、SAST/DAST/SCAの役割を整理する。'],
      ['Provenance', 'commit、CI run、artifact、release noteを紐づける。'],
      ['Sign', 'artifact signingとverificationの導入手順を書く。'],
      ['Disclose', 'security advisory、CVE/CVSS、responsible disclosureを確認する。'],
    ],
    commands: [
      'npm --prefix app audit --omit=dev --audit-level=high',
      'scripts/world_class_hands_on_check.sh supply-chain',
      'sed -n "1,220p" SECURITY.md',
      'sed -n "1,220p" docs/templates/vulnerability-remediation-pr.md',
    ],
    tools: [
      ['SBOM', 'component、version、license、vulnerabilityを一覧化する。'],
      ['SAST/DAST/SCA', 'コード、実行中API、依存を別々に検査する。'],
      ['Secret scanning', '漏洩検知とrotationを行う。'],
      ['Signing/provenance', 'artifactの出自を検証する。'],
    ],
    evidence: [
      'SBOM/SAST/DAST/SCA coverage map',
      'CI run、commit、artifactの対応',
      'secret rotation手順',
      'security advisoryとrelease note案',
    ],
    worldClass: [
      'CycloneDX/Syft、cosign、SLSA provenanceを実行する。',
      'container image scanとlicense policyをCIに入れる。',
      'security advisory dry-runを実施する。',
    ],
  },
  {
    id: 'S30',
    slug: 's30-detection-edr-case',
    title: 'Detection Engineering・EDR Case Management',
    layer: 'Detection/EDR',
    level: '上級',
    roles: ['Whitehat', 'SRE'],
    score: 4,
    summary: 'Sigma、YARA、Suricata、MITRE ATT&CK、false positive tuning、event normalization、SIEM query、case managementを扱う。',
    concept: 'Detection engineeringはalertを増やすことではなく、攻撃仮説、telemetry、正規化、誤検知調整、case判断を一つの運用にすることです。',
    examples: [
      'Suricata ruleをMITRE techniqueへ対応させ、何を検知できて何を検知できないかを書く。',
      'Sigma/YARAはvendor非依存の検知意図として保存し、SIEM queryへ変換する。',
      'false positiveが多いruleはthreshold、allowlist、context enrichmentで調整する。',
    ],
    objective: '検知ルールを作るだけでなく、case triage、owner、severity、closure reasonまで運用できるようにする。',
    flow: [
      ['Hypothesis', '攻撃仮説と必要telemetryを定義する。'],
      ['Normalize', 'source.ip、user.name、process.name、event.actionなどのfieldを揃える。'],
      ['Map', 'MITRE ATT&CK techniqueとruleを対応させる。'],
      ['Tune', 'false positive/false negativeを評価する。'],
      ['Case', 'case management形式でtimeline、severity、closureを書く。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p19',
      'docker exec soc-lab-suricata tail -50 /var/log/suricata/fast.log',
      'scripts/world_class_hands_on_check.sh detection',
      'sed -n "1,220p" docs/soc-playbook.md',
      'sed -n "1,220p" docs/templates/incident-report.md',
    ],
    tools: [
      ['Sigma/YARA', 'vendor非依存の検知意図を書く。'],
      ['Suricata', 'network detectionの実ルールを検証する。'],
      ['MITRE ATT&CK', '検知coverageとgapを説明する。'],
      ['SIEM/Case management', 'alertをincident判断へ変換する。'],
    ],
    evidence: [
      'attack hypothesisとtelemetry要件',
      'MITRE mapping',
      'false positive tuning結果',
      'case timelineとclosure reason',
    ],
    worldClass: [
      'SigmaをElastic/KQLへ変換して実検索する。',
      'case management systemへticketを作る。',
      'detection-as-codeのunit testを追加する。',
    ],
  },
  {
    id: 'S31',
    slug: 's31-endpoint-sysmon-malware',
    title: 'Endpoint Telemetry・Sysmon・Malware Behavior',
    layer: 'Endpoint/EDR',
    level: '上級',
    roles: ['Whitehat', 'SRE'],
    score: 3,
    summary: 'process tree、Windows/Linux telemetry、auditd、Sysmon、kernel/userland境界、malware behavior、sandboxingを扱う。',
    concept: 'Endpoint/EDRでは、processが何を起動し、どのfile/network/registryへ触れたかを因果関係として追います。抽象的には、振る舞いから悪性/正常を判断する訓練です。',
    examples: [
      'Linuxではauditd execve、file write、uid changeをprocess timelineにする。',
      'WindowsではSysmon Event ID 1/3/7/11などでprocess/network/image/fileを追う。',
      'malware behaviorは実malwareを動かさず、sandboxで観測する前提と安全範囲を定義する。',
    ],
    objective: 'endpoint telemetryをnetwork/API/SIEM eventと相関し、EDR製品に依存しない調査力を作る。',
    flow: [
      ['Collect', 'auditdのfile/process/privilege eventを確認する。'],
      ['Model', 'process treeとparent-child関係を書く。'],
      ['Map', 'Sysmon相当のWindows telemetryに置き換える。'],
      ['Behavior', 'persistence、credential access、lateral movementなどの振る舞いを分類する。'],
      ['Contain', 'isolation、kill process、credential rotationの判断を書く。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p19',
      'sed -n "1,220p" auditd/README.md',
      'scripts/world_class_hands_on_check.sh endpoint',
      'sed -n "1,220p" docs/templates/incident-report.md',
    ],
    tools: [
      ['auditd', 'Linux endpoint telemetryを収集する。'],
      ['Sysmon', 'Windows process/network/file/image telemetryの代表例。'],
      ['Process tree', 'parent-child関係から侵害経路を読む。'],
      ['Sandbox', 'malware behaviorを隔離環境で観測する。'],
    ],
    evidence: [
      'process treeとtimeline',
      'auditd/Sysmon field mapping',
      'malware behavior分類',
      'containmentとcredential rotation判断',
    ],
    worldClass: [
      'Windows labとSysmon configを追加する。',
      'EDR telemetryをSIEM正規化schemaへ流す。',
      'malware sandbox reportのtriage演習を行う。',
    ],
  },
  {
    id: 'S32',
    slug: 's32-performance-flamegraph-db',
    title: 'Performance Engineering・Flamegraph・DB Query Plan',
    layer: 'Performance',
    level: '上級',
    roles: ['Backend', 'SRE'],
    score: 4,
    summary: 'profiling、load test、p95/p99、connection pool、N+1、GC、CPU flamegraph、memory leak、DB index/query planを扱う。',
    concept: 'Performance engineeringは速くする作業ではなく、どのresourceがどのSLOを壊しているかを証拠で特定し、変更の副作用を測る作業です。',
    examples: [
      'p50は正常でもp99が悪い場合、一部requestのDB queryやlockが原因かもしれない。',
      'N+1は平均負荷では見えにくく、データ量増加で急にSLOを壊す。',
      'flamegraphはCPU hot path、heap profileはmemory leak、query planはDB bottleneckを見る。',
    ],
    objective: '性能劣化をCPU、memory、GC、DB、network、poolに分解し、改善PRの証跡を作れるようにする。',
    flow: [
      ['Measure', 'load testでp95/p99とfailureを取る。'],
      ['Hypothesize', 'CPU、memory、DB、connection pool、networkの仮説を立てる。'],
      ['Profile', 'ラボではNode build/testとOS観測を使い、実務ではflamegraph/query planへ拡張する。'],
      ['Fix safely', 'index、pagination、pool、cache、backpressureの副作用を比較する。'],
      ['Verify', 'before/afterのSLOとrollback条件を記録する。'],
    ],
    commands: [
      'REQUESTS=120 CONCURRENCY=8 scripts/load_hands_on_tests.sh',
      'npm --prefix app test',
      'scripts/world_class_hands_on_check.sh performance',
      'sed -n "1,220p" docs/templates/backend-test-report.md',
    ],
    tools: [
      ['Load test', 'p95/p99、throughput、failureを測る。'],
      ['Flamegraph/profiler', 'CPU hot pathを特定する。'],
      ['DB query plan', 'index、scan、join、sortを確認する。'],
      ['Heap/GC tools', 'memory leakとGC pauseを調査する。'],
    ],
    evidence: [
      'p95/p99とthroughput',
      'bottleneck仮説と反証',
      'query plan/index/pool設計',
      'before/afterとrollback条件',
    ],
    worldClass: [
      'Clinic.js/0x/perfでNode flamegraphを生成する。',
      'PostgreSQL EXPLAIN ANALYZEをintegration labへ入れる。',
      'performance regression gateをCIに追加する。',
    ],
  },
  {
    id: 'S33',
    slug: 's33-gitops-progressive-delivery',
    title: 'GitOps・Progressive Delivery・OSS Governance',
    layer: 'Release/OSS',
    level: 'Principal',
    roles: ['SRE', 'Backend', 'Whitehat'],
    score: 4,
    summary: 'GitOps、progressive delivery、feature flag、blue-green/canary、rollback safety、artifact signing、CVE/CVSS、responsible disclosure、branch protection、license complianceを扱う。',
    concept: 'Release engineeringとOSS運用は、変更を速く出すことではなく、誰が何をreviewし、どう段階的に出し、問題時にどう戻し、利用者へどう伝えるかを決めることです。',
    examples: [
      'feature flagで新機能をdeployとreleaseに分け、障害時はflag offで戻す。',
      'canaryで1% trafficだけ新versionへ流し、SLOが悪化したら自動/手動rollbackする。',
      'security advisoryでは影響version、回避策、修正版、CVSS、謝辞、公開タイミングを管理する。',
    ],
    objective: '安全なrelease、rollback、開示、OSS complianceを一つのoperating modelとして説明できるようにする。',
    flow: [
      ['Plan', 'release scope、risk、migration compatibility、rollbackを整理する。'],
      ['Progress', 'blue-green/canary/feature flagの選択理由を書く。'],
      ['Protect', 'branch protection、review、CI required checks、artifact signingを確認する。'],
      ['Disclose', 'security advisory、CVE/CVSS、responsible disclosureを準備する。'],
      ['Review', 'release note、license、compliance、post-release monitoringを確認する。'],
    ],
    commands: [
      'scripts/learning_phase.sh start p19',
      'scripts/lab_quality_gate.sh',
      'scripts/world_class_hands_on_check.sh governance',
      'sed -n "1,220p" SECURITY.md',
      'sed -n "1,220p" CONTRIBUTING.md',
    ],
    tools: [
      ['GitOps', 'Git diffとPR reviewを運用の正とする。'],
      ['Feature flag', 'deployとreleaseを分離する。'],
      ['Canary/blue-green', '段階的にtrafficを移す。'],
      ['Security advisory', 'CVE/CVSSとresponsible disclosureを管理する。'],
    ],
    evidence: [
      'release checklist',
      'canary/rollback条件',
      'branch protectionとrequired checks',
      'advisory、CVE/CVSS、license complianceの確認',
    ],
    worldClass: [
      'Argo CD/FluxでGitOps環境を構築する。',
      'Flag管理とautomated rollbackを実装する。',
      'release signing、provenance、advisory dry-runをCIに入れる。',
    ],
  },
];

scenarios.push(...advancedScenarios);

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function list(items) {
  return `<ul>${items.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}</ul>`;
}

function commandBlock(commands) {
  return `<pre><code>${escapeHtml(commands.join('\n'))}</code></pre>`;
}

function toolTable(tools) {
  return `<table><thead><tr><th>Tool</th><th>使い方</th></tr></thead><tbody>${tools
    .map(([tool, use]) => `<tr><td><strong>${escapeHtml(tool)}</strong></td><td>${escapeHtml(use)}</td></tr>`)
    .join('')}</tbody></table>`;
}

function scenarioConcept(scenario) {
  return scenario.concept || `${scenario.title}は、単発の攻撃手順ではなく、${scenario.objective}`;
}

function scenarioExamples(scenario) {
  return scenario.examples || scenario.flow.slice(0, 3).map(([step, text]) => `${step}: ${text}`);
}

function scenarioPrerequisites(scenario) {
  return scenario.prerequisites || [
    'Docker DesktopまたはDocker Engineが起動している。',
    'docker compose config -q が通り、対象service/profileを説明できる。',
    `対象はローカルラボと${scenario.id}のHTMLに書かれた範囲だけに限定する。`,
  ];
}

function scenarioSafety(scenario) {
  const safety = [
    '第三者環境、公共IP、許可のないcloud accountには実行しない。',
    'payload、scan、負荷はHTMLに書かれたローカル対象へ限定する。',
  ];
  const context = `${scenario.title} ${scenario.summary} ${scenario.layer}`;

  if (/BGP|Anycast|CDN|Cloud|IAM|KMS|Terraform|OPA/.test(context)) {
    safety.push('実cloud、BGP、CDN、組織policyは変更せず、設計レビュー、サンプルログ、ローカル検証に限定する。');
  }
  if (/DoS|Session|Load|Backpressure|Performance|負荷/.test(context)) {
    safety.push('負荷値は小さく始め、SLO悪化を確認したらすぐ停止できる状態で実行する。');
  }
  if (/RCE|Upload|SSRF|BOLA|SQL|Traversal|権限|改変/.test(context)) {
    safety.push('攻撃payloadは教材内の明示されたendpoint、file、containerだけに向ける。');
  }

  return scenario.safety || safety;
}

function scenarioObservationPoints(scenario) {
  return scenario.observations || [
    '実行コマンドの開始時刻、対象、終了時刻を記録する。',
    'HTTP status、アプリログ、検知ログ、メトリクスのどれで成功/失敗を証明するかを決める。',
    `合格証跡として「${scenario.evidence[0]}」を第三者が追える形で残す。`,
  ];
}

function scenarioCommonMistakes(scenario) {
  return scenario.commonMistakes || [
    '攻撃が成功したことと、検知や防御が成功したことを混同する。',
    'source、timestamp、request、検索条件を残さず、後から再現できない。',
    'ローカルで動いた事実だけで完了扱いにし、本番で必要な追加統制を説明しない。',
  ];
}

function scenarioSelfReview(scenario) {
  return scenario.selfReview || [
    `${scenario.title}で守りたい資産と失敗条件を一文で説明できるか。`,
    'どのログ、テスト、メトリクスが判断根拠かを第三者が追えるか。',
    '本番導入時の追加統制、owner、rollback条件を言えるか。',
  ];
}

function flowMarkup(flow) {
  return `<ol class="flow">${flow
    .map(([step, text]) => `<li><span>${escapeHtml(step)}</span><p>${escapeHtml(text)}</p></li>`)
    .join('')}</ol>`;
}

function rating(score) {
  const labels = ['不足', '入門', '基礎良好', '実務中級', '実務上級'];
  return `<span class="score score-${score}">${score}/5 ${labels[score] || ''}</span>`;
}

function layout(title, body, activeId = '') {
  const nav = scenarios
    .map((scenario) => {
      const href = `${scenario.slug}.html`;
      const active = scenario.id === activeId ? ' aria-current="page"' : '';
      return `<a${active} href="${href}">${scenario.id}</a>`;
    })
    .join('');

  return `<!doctype html>
<html lang="ja">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} - Secure Learn</title>
  <link rel="stylesheet" href="assets/scenario.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="index.html">Secure Learn Scenario Guides</a>
    <nav aria-label="Scenario navigation">${nav}</nav>
  </header>
  <main>
${body}
  </main>
</body>
</html>
`;
}

function scenarioPage(scenario) {
  const related = scenarios
    .filter((item) => item.id !== scenario.id && item.roles.some((role) => scenario.roles.includes(role)))
    .slice(0, 4);

  return layout(
    `${scenario.id} ${scenario.title}`,
    `    <section class="scenario-head">
      <p class="eyebrow">${escapeHtml(scenario.id)} / ${escapeHtml(scenario.layer)} / ${escapeHtml(scenario.level)}</p>
      <h1>${escapeHtml(scenario.title)}</h1>
      <p class="lead">${escapeHtml(scenario.summary)}</p>
      <div class="meta-row">
        ${rating(scenario.score)}
        ${scenario.roles.map((role) => `<span class="pill">${escapeHtml(role)}</span>`).join('')}
      </div>
    </section>

    <section class="grid two">
      <article>
        <h2>抽象的に何を学ぶか</h2>
        <p>${escapeHtml(scenarioConcept(scenario))}</p>
      </article>
      <article>
        <h2>具体例</h2>
        ${list(scenarioExamples(scenario))}
      </article>
    </section>

    <section class="grid two">
      <article>
        <h2>目的</h2>
        <p>${escapeHtml(scenario.objective)}</p>
      </article>
      <article>
        <h2>世界レベル評価</h2>
        <p>${scenario.score >= 4 ? '実務上級に近い構成です。証跡、修正、運用判断まで扱えます。' : '基礎から実務中級の土台を作る構成です。高度領域はS16以降の専門シナリオへ接続します。'}</p>
      </article>
    </section>

    <section class="grid two">
      <article>
        <h2>事前準備</h2>
        ${list(scenarioPrerequisites(scenario))}
      </article>
      <article>
        <h2>安全境界</h2>
        ${list(scenarioSafety(scenario))}
      </article>
    </section>

    <section>
      <h2>Hands-on Flow</h2>
      ${flowMarkup(scenario.flow)}
    </section>

    <section class="grid two">
      <article>
        <h2>実行コマンド</h2>
        ${commandBlock(scenario.commands)}
      </article>
      <article>
        <h2>合格証跡</h2>
        ${list(scenario.evidence)}
      </article>
    </section>

    <section>
      <h2>ツール活用</h2>
      ${toolTable(scenario.tools)}
    </section>

    <section class="grid three">
      <article>
        <h2>観測ポイント</h2>
        ${list(scenarioObservationPoints(scenario))}
      </article>
      <article>
        <h2>よくある失敗</h2>
        ${list(scenarioCommonMistakes(scenario))}
      </article>
      <article>
        <h2>セルフレビュー</h2>
        ${list(scenarioSelfReview(scenario))}
      </article>
    </section>

    <section class="grid two">
      <article>
        <h2>Whitehat / SRE / Backend 観点</h2>
        ${list([
          scenario.roles.includes('Whitehat') ? 'Whitehat: 攻撃を許可範囲に限定し、再現性と検知証跡を残す。' : 'Whitehat: このシナリオでは補助観点として扱う。',
          scenario.roles.includes('SRE') ? 'SRE: SLO、可用性、レイテンシ、復旧判断へ接続する。' : 'SRE: 影響がある場合だけSLO差分を確認する。',
          scenario.roles.includes('Backend') ? 'Backend: 入力検証、契約、テスト、エラー安全性を確認する。' : 'Backend: サービス露出、ログ、HTTP契約との関係を確認する。',
        ])}
      </article>
      <article>
        <h2>世界レベルへ足す課題</h2>
        ${list(scenario.worldClass)}
      </article>
    </section>

    <section>
      <h2>関連シナリオ</h2>
      <div class="links">${related.map((item) => `<a href="${item.slug}.html">${item.id} ${escapeHtml(item.title)}</a>`).join('')}</div>
    </section>
`,
    scenario.id,
  );
}

function indexPage() {
  const rows = scenarios
    .map(
      (scenario) => `<tr>
        <td><a href="${scenario.slug}.html">${scenario.id}</a></td>
        <td>${escapeHtml(scenario.title)}</td>
        <td>${escapeHtml(scenario.layer)}</td>
        <td>${scenario.roles.map(escapeHtml).join(', ')}</td>
        <td>${rating(scenario.score)}</td>
        <td>${escapeHtml(scenario.summary)}</td>
      </tr>`,
    )
    .join('');

  const roleCoverage = [
    ['Whitehat', scenarios.filter((s) => s.roles.includes('Whitehat')).length],
    ['SRE', scenarios.filter((s) => s.roles.includes('SRE')).length],
    ['Backend', scenarios.filter((s) => s.roles.includes('Backend')).length],
  ];

  return layout(
    'Scenario Index',
    `    <section class="scenario-head">
      <p class="eyebrow">World-class readiness review</p>
      <h1>シナリオ別ハンズオンHTML</h1>
      <p class="lead">${scenarios.length}シナリオを、抽象説明、具体例、実行フロー、確認項目、ツール活用、証跡、世界レベルへの追加課題まで追える形に整理しています。</p>
    </section>

    <section class="grid three">
      ${roleCoverage
        .map(([role, count]) => `<article><h2>${role}</h2><p class="big">${count}/${scenarios.length}</p><p>この観点を主対象または副対象として扱うシナリオ数です。</p></article>`)
        .join('')}
    </section>

    <section>
      <h2>総合評価</h2>
      <p>現在のSecure Learnは、基礎15シナリオに加えて、Linux internals、cloud/IAM、IaC、Kubernetes platform、observability、distributed systems、backend production、supply chain、EDR、release governanceまでを順番に学ぶ高度シナリオを含みます。各ページは「抽象的に何を学ぶか」と「手元で何をするか」を分け、実務で説明可能な証跡へ接続します。</p>
      ${list(globalGaps)}
    </section>

    <section>
      <h2>シナリオ一覧</h2>
      <table>
        <thead><tr><th>ID</th><th>Scenario</th><th>Layer</th><th>Roles</th><th>Readiness</th><th>狙い</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </section>

    <section>
      <h2>参照した評価軸</h2>
      <table>
        <thead><tr><th>Reference</th><th>使いどころ</th></tr></thead>
        <tbody>${benchmarks
          .map((item) => `<tr><td><a href="${item.href}">${escapeHtml(item.label)}</a></td><td>${escapeHtml(item.use)}</td></tr>`)
          .join('')}</tbody>
      </table>
    </section>
`,
  );
}

function writeCss() {
  const css = `:root {
  color-scheme: light;
  --bg: #f5f7f9;
  --panel: #ffffff;
  --text: #18202a;
  --muted: #5b6472;
  --line: #d7dde5;
  --accent: #0f766e;
  --accent-2: #3451a4;
  --warn: #b45309;
  --danger: #b91c1c;
  --ok: #15803d;
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  line-height: 1.6;
}

a { color: var(--accent-2); text-decoration-thickness: 1px; }

.topbar {
  position: sticky;
  top: 0;
  z-index: 10;
  display: flex;
  align-items: center;
  gap: 18px;
  padding: 12px 24px;
  border-bottom: 1px solid var(--line);
  background: rgba(255, 255, 255, 0.96);
  backdrop-filter: blur(10px);
}

.brand {
  flex: 0 0 auto;
  color: var(--text);
  font-weight: 700;
  text-decoration: none;
}

nav {
  display: flex;
  gap: 6px;
  overflow-x: auto;
  padding-bottom: 2px;
}

nav a {
  display: inline-flex;
  min-width: 38px;
  min-height: 32px;
  align-items: center;
  justify-content: center;
  border: 1px solid var(--line);
  border-radius: 6px;
  color: var(--muted);
  text-decoration: none;
  font-size: 13px;
}

nav a[aria-current="page"] {
  border-color: var(--accent);
  color: var(--accent);
  font-weight: 700;
}

main {
  width: min(1180px, calc(100% - 32px));
  margin: 0 auto;
  padding: 28px 0 56px;
}

.scenario-head {
  border-bottom: 1px solid var(--line);
  padding: 18px 0 24px;
  margin-bottom: 22px;
}

.eyebrow {
  color: var(--accent);
  font-weight: 700;
  text-transform: uppercase;
  font-size: 13px;
}

h1, h2 {
  line-height: 1.2;
  margin: 0 0 12px;
  letter-spacing: 0;
}

h1 { font-size: 40px; }
h2 { font-size: 22px; }

.lead {
  max-width: 880px;
  color: var(--muted);
  font-size: 18px;
}

section {
  margin-top: 24px;
}

article, table, pre {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
}

article {
  padding: 18px;
}

.grid {
  display: grid;
  gap: 16px;
}

.grid.two { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.grid.three { grid-template-columns: repeat(3, minmax(0, 1fr)); }

.meta-row, .links {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}

.pill, .score {
  display: inline-flex;
  align-items: center;
  min-height: 30px;
  padding: 4px 10px;
  border-radius: 999px;
  border: 1px solid var(--line);
  background: var(--panel);
  font-size: 13px;
  font-weight: 700;
}

.score-4, .score-5 { color: var(--ok); border-color: #86efac; }
.score-3 { color: var(--warn); border-color: #facc15; }
.score-0, .score-1, .score-2 { color: var(--danger); border-color: #fca5a5; }

.big {
  font-size: 36px;
  font-weight: 800;
  margin: 0;
}

.flow {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 12px;
  padding: 0;
  list-style: none;
}

.flow li {
  min-height: 148px;
  padding: 14px;
  border: 1px solid var(--line);
  border-top: 4px solid var(--accent);
  border-radius: 8px;
  background: var(--panel);
}

.flow span {
  display: block;
  margin-bottom: 8px;
  color: var(--accent);
  font-weight: 800;
}

.flow p { margin: 0; color: var(--muted); }

pre {
  overflow-x: auto;
  padding: 16px;
}

code {
  font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
  font-size: 13px;
}

table {
  width: 100%;
  border-collapse: collapse;
  overflow: hidden;
}

th, td {
  padding: 12px;
  border-bottom: 1px solid var(--line);
  text-align: left;
  vertical-align: top;
}

th {
  background: #eef3f7;
  color: #2a3441;
}

tr:last-child td { border-bottom: 0; }

ul {
  padding-left: 20px;
  margin: 0;
}

li + li { margin-top: 6px; }

.links a {
  display: inline-flex;
  padding: 8px 10px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--panel);
  text-decoration: none;
}

@media (max-width: 900px) {
  .topbar { align-items: flex-start; flex-direction: column; }
  h1 { font-size: 30px; }
  .grid.two, .grid.three, .flow { grid-template-columns: 1fr; }
}
`;

  fs.writeFileSync(path.join(assetDir, 'scenario.css'), css);
}

function main() {
  fs.mkdirSync(assetDir, { recursive: true });
  writeCss();
  fs.writeFileSync(path.join(outDir, 'index.html'), indexPage());
  for (const scenario of scenarios) {
    fs.writeFileSync(path.join(outDir, `${scenario.slug}.html`), scenarioPage(scenario));
  }
  console.log(`Generated ${scenarios.length + 1} HTML files in ${path.relative(root, outDir)}`);
}

main();
