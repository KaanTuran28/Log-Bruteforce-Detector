# Log Bruteforce Detector

![CI](https://github.com/KaanTuran28/Log-Bruteforce-Detector/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

<p align="center"><b><a href="#english">English</a></b> · <b><a href="#türkçe">Türkçe</a></b></p>

---

## English

A lightweight, dependency-free Python tool that parses SSH `auth.log`-style files and flags brute-force login attempts and possible compromises.

## Overview

Blue Team / SOC analysts routinely need to triage SSH authentication logs for brute-force activity. This tool aggregates failed and accepted login events per source IP and produces a Markdown report with a clear severity verdict for each offending IP:

- **HIGH — possible compromise**: failed attempts followed by a successful login from the same IP.
- **MEDIUM — brute-force suspected**: failed attempts at or above the configured threshold.
- **LOW — below threshold**: some failed attempts, but under the threshold.

## Installation

Requires Python 3.9+. No external runtime dependencies.

```bash
git clone <this-repo-url>
cd Log-Bruteforce-Detector
pip install -e .
```

This installs a `log-bruteforce-detector` console command. You can also just run the script directly without installing:

```bash
python log_bruteforce_detector.py --log sample_logs/auth.log --threshold 5
```

## Usage

```bash
log-bruteforce-detector --log sample_logs/auth.log --threshold 5 --output sample_report.md
log-bruteforce-detector --log sample_logs/auth.log --threshold 5 --format json --output report.json
log-bruteforce-detector --help
```

| Flag | Default | Description |
|---|---|---|
| `--log` | *(required)* | Path to the auth log file |
| `--threshold` | `5` | Failed-attempt count that triggers a MEDIUM verdict |
| `--output` | `sample_report.md` | Path to write the report |
| `--format` | `markdown` | `markdown` or `json` |
| `--fail-on` | `none` | `none`, `medium`, or `high` — exit code `1` if a finding at/above this severity exists |

## CI Integration

`--fail-on` lets you gate a pipeline on the verdict instead of just generating a report:

```bash
# fail the build if any IP looks like a possible compromise
log-bruteforce-detector --log /var/log/auth.log --fail-on high
```

```yaml
# GitHub Actions step
- name: Check for SSH brute-force / compromise
  run: log-bruteforce-detector --log /var/log/auth.log --fail-on high
```

Default is `none` (always exits `0`) so ad-hoc report generation is unaffected.

## How It Works

1. Reads the log line by line, matching `Failed password ...` and `Accepted password/publickey ...` patterns via regex.
2. Aggregates per source IP: failed attempt count, unique usernames tried, first/last seen timestamps.
3. If an IP has failed attempts followed by a later successful login, it's flagged as a possible compromise regardless of the threshold.
4. Writes a Markdown table sorted by failed-attempt count, plus a one-line summary.

## Example Output

Run against [`sample_logs/auth.log`](./sample_logs/auth.log):

```
Flagged 3 IP(s): 1 HIGH, 1 MEDIUM, 1 LOW.
Report written to sample_report.md
```

| IP | Failed Attempts | Unique Usernames | First Seen | Last Seen | Verdict |
|---|---|---|---|---|---|
| 203.0.113.45 | 9 | 6 | Aug 20 03:10:01 | Aug 20 03:10:19 | HIGH — possible compromise |
| 192.0.2.200 | 6 | 2 | Aug 20 03:22:01 | Aug 20 03:22:11 | MEDIUM — brute-force suspected |
| 198.51.100.77 | 4 | 2 | Aug 20 03:30:01 | Aug 20 03:31:02 | LOW — below threshold |

Full report: [`sample_report.md`](./sample_report.md)

## Testing

```bash
pip install -r requirements-dev.txt
pytest -v
ruff check .
```

CI runs the same lint + test suite on every push via GitHub Actions (see `.github/workflows/ci.yml`).

## Project Structure

```
Log-Bruteforce-Detector/
├── log_bruteforce_detector.py
├── pyproject.toml
├── tests/
│   └── test_log_bruteforce_detector.py
├── sample_logs/
│   └── auth.log
├── sample_report.md
├── requirements.txt
├── requirements-dev.txt
├── .github/workflows/ci.yml
├── README.md
├── DURUM.md
└── LICENSE
```

## License

MIT — see [LICENSE](./LICENSE).

---

## Türkçe

Hafif, bağımlılığı olmayan bir Python aracı; SSH `auth.log` tarzı dosyaları ayrıştırır ve brute-force (kaba kuvvet) giriş denemelerini ve olası ele geçirilmeleri (compromise) işaretler.

## Genel Bakış

Blue Team / SOC analistleri, SSH kimlik doğrulama loglarını brute-force etkinliği açısından rutin olarak triyaj etmek zorundadır. Bu araç, her kaynak IP için başarısız ve kabul edilen giriş olaylarını toplar ve her sorunlu IP için net bir önem derecesi (severity) sonucu içeren bir Markdown raporu üretir:

- **HIGH — olası ele geçirilme**: aynı IP'den başarısız denemelerin ardından başarılı bir giriş.
- **MEDIUM — brute-force şüphesi**: yapılandırılmış eşik değerinde veya üzerinde başarısız deneme.
- **LOW — eşiğin altında**: bazı başarısız denemeler var, ancak eşiğin altında.

## Kurulum

Python 3.9+ gerektirir. Harici çalışma zamanı bağımlılığı yoktur.

```bash
git clone <this-repo-url>
cd Log-Bruteforce-Detector
pip install -e .
```

Bu, `log-bruteforce-detector` adında bir konsol komutu kurar. Kurulum yapmadan da betiği doğrudan çalıştırabilirsiniz:

```bash
python log_bruteforce_detector.py --log sample_logs/auth.log --threshold 5
```

## Kullanım

```bash
log-bruteforce-detector --log sample_logs/auth.log --threshold 5 --output sample_report.md
log-bruteforce-detector --log sample_logs/auth.log --threshold 5 --format json --output report.json
log-bruteforce-detector --help
```

| Flag | Varsayılan | Açıklama |
|---|---|---|
| `--log` | *(zorunlu)* | Auth log dosyasının yolu |
| `--threshold` | `5` | MEDIUM sonucunu tetikleyen başarısız deneme sayısı |
| `--output` | `sample_report.md` | Raporun yazılacağı yol |
| `--format` | `markdown` | `markdown` veya `json` |
| `--fail-on` | `none` | `none`, `medium` veya `high` — bu önem derecesinde veya üzerinde bir bulgu varsa çıkış kodu `1` olur |

## CI Entegrasyonu

`--fail-on`, yalnızca bir rapor üretmek yerine bir hattı (pipeline) sonuca göre kısıtlamanızı sağlar:

```bash
# fail the build if any IP looks like a possible compromise
log-bruteforce-detector --log /var/log/auth.log --fail-on high
```

```yaml
# GitHub Actions step
- name: Check for SSH brute-force / compromise
  run: log-bruteforce-detector --log /var/log/auth.log --fail-on high
```

Varsayılan değer `none`'dur (her zaman `0` ile çıkış yapar), böylece geçici (ad-hoc) rapor üretimi etkilenmez.

## Nasıl Çalışır

1. Logu satır satır okur, `Failed password ...` ve `Accepted password/publickey ...` kalıplarını regex ile eşleştirir.
2. Kaynak IP başına toplar: başarısız deneme sayısı, denenen benzersiz kullanıcı adları, ilk/son görülme zaman damgaları.
3. Bir IP'de başarısız denemelerin ardından daha sonra başarılı bir giriş varsa, eşik değerinden bağımsız olarak olası bir ele geçirilme (compromise) olarak işaretlenir.
4. Başarısız deneme sayısına göre sıralanmış bir Markdown tablosu ile tek satırlık bir özet yazar.

## Örnek Çıktı

[`sample_logs/auth.log`](./sample_logs/auth.log) dosyasına karşı çalıştırıldığında:

```
Flagged 3 IP(s): 1 HIGH, 1 MEDIUM, 1 LOW.
Report written to sample_report.md
```

| IP | Başarısız Deneme | Benzersiz Kullanıcı Adı | İlk Görülme | Son Görülme | Sonuç |
|---|---|---|---|---|---|
| 203.0.113.45 | 9 | 6 | Aug 20 03:10:01 | Aug 20 03:10:19 | HIGH — possible compromise |
| 192.0.2.200 | 6 | 2 | Aug 20 03:22:01 | Aug 20 03:22:11 | MEDIUM — brute-force suspected |
| 198.51.100.77 | 4 | 2 | Aug 20 03:30:01 | Aug 20 03:31:02 | LOW — below threshold |

Tam rapor: [`sample_report.md`](./sample_report.md)

## Test

```bash
pip install -r requirements-dev.txt
pytest -v
ruff check .
```

CI, her push işleminde GitHub Actions üzerinden aynı lint + test paketini çalıştırır (bkz. `.github/workflows/ci.yml`).

## Proje Yapısı

```
Log-Bruteforce-Detector/
├── log_bruteforce_detector.py
├── pyproject.toml
├── tests/
│   └── test_log_bruteforce_detector.py
├── sample_logs/
│   └── auth.log
├── sample_report.md
├── requirements.txt
├── requirements-dev.txt
├── .github/workflows/ci.yml
├── README.md
├── DURUM.md
└── LICENSE
```

## Lisans

MIT — bkz. [LICENSE](./LICENSE).

---
