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
  'API Securityの上位領域では、IDOR/BOLA、SSRF、unsafe file upload、CSRF/CORS、business logic abuseを追加すると世界レベルに近づく。',
  'SRE領域では、burn-rate alert、metrics/traces、canary、rollback drill、backup/restore、capacity planningを実測化する余地がある。',
  'Backend領域では、schema validation、pagination、migration/rollback、transaction、concurrency、contract compatibilityをさらに深掘りできる。',
  'Cloud領域では、IAM/RBAC、Ingress/TLS、image scan、SBOM、secret rotation、policy-as-codeをCIへ組み込む余地がある。',
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
        <h2>目的</h2>
        <p>${escapeHtml(scenario.objective)}</p>
      </article>
      <article>
        <h2>世界レベル評価</h2>
        <p>${scenario.score >= 4 ? '実務上級に近い構成です。証跡、修正、運用判断まで扱えます。' : '基礎から実務中級までは有効です。世界レベルには追加課題の実測化が必要です。'}</p>
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
      <p class="lead">15シナリオを、実行フロー、確認項目、ツール活用、証跡、世界レベルへの追加課題まで追える形に整理しています。</p>
    </section>

    <section class="grid three">
      ${roleCoverage
        .map(([role, count]) => `<article><h2>${role}</h2><p class="big">${count}/15</p><p>この観点を主対象または副対象として扱うシナリオ数です。</p></article>`)
        .join('')}
    </section>

    <section>
      <h2>総合評価</h2>
      <p>現在のSecure Learnは、ネットワーク偵察、認証攻撃、SQLi修正、OS監査、SLO/incident drill、Kubernetes基礎までを持つため、実務中級から上級入口の教材として成立しています。世界レベルを名乗るには、API business logic、cloud/IAM、observability、supply chain、release engineeringをさらに実測化する余地があります。</p>
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
