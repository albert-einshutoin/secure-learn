# Supply Chain Security Track

OSSとして信頼されるには、アプリの脆弱性だけでなく、依存関係、CI、コンテナ、秘密情報を継続的に検査します。

## 必須チェック

| チェック | 目的 | 初期対応 |
|----------|------|----------|
| npm audit | Node依存の既知脆弱性 | CI済み |
| Docker Compose config | ラボ構成の構文検証 | CI済み |
| Bash syntax | 演習スクリプトの壊れ検知 | CI追加 |
| Suricata `-T` | ルールparser検証 | CI追加 |
| Secret scanning | 秘密情報混入検知 | GitGuardian / Gitleaks |
| SAST | 危険コードパターン検知 | Semgrep |
| SCA/OSV | ecosystem横断の脆弱性検知 | OSV Scanner |
| Image scan | コンテナCVE検知 | Trivy |
| SBOM | 依存関係の棚卸し | CycloneDX/SPDX |

## 運用方針

- CIで必ず落とすもの: build、unit test、compose config、bash syntax、Suricata parser、high以上のproduction npm audit
- 最初はwarningで運用するもの: container image CVE、SAST medium、SBOM差分
- PRで説明必須なもの: security exception、false positive、accepted risk、rollback

