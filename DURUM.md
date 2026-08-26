# Durum Günlüğü

> En üstteki kayıt en güncelidir. Her çalışma sonrası buraya kısa bir not düşülür.

---

## 2026-08-21 — CI gating için `--fail-on` eklendi

- Konu: `--fail-on {none,medium,high}` bayrağı eklendi — CI/CD pipeline'larında bulguya göre build'i kırabilmek için. Varsayılan `none` (mevcut davranış korunuyor, geriye dönük uyumlu).
- 4 yeni test eklendi (10 → 14), hepsi geçti. Ruff temiz. README'ye `## CI Integration` bölümü eklendi.
- Durum: ✅ Henüz push edilmedi (repo hâlâ local, kullanıcı tercihiyle push bu turda yapılmadı).

**Sıradaki iş:** GitHub'da `Log-Bruteforce-Detector` adıyla repo aç, git init + push.

---

## 2026-08-20 — Paketleme, JSON çıktı ve lint eklendi

- Konu: `pyproject.toml` ile pip kurulabilir hale getirildi (`pip install -e .` → `log-bruteforce-detector` komutu), `--format json` eklendi, ruff lint + CI lint job'u eklendi.
- Durum: ✅ 10/10 test geçiyor, ruff temiz, `pip install -e .` gerçek bir venv'de kurulup her iki format da (markdown/json) çalıştırılarak doğrulandı, sonra temizlendi.

**Sıradaki iş:** GitHub'da `Log-Bruteforce-Detector` adıyla repo aç, git init + push.

---

## 2026-08-20 — Test suite ve CI eklendi
- Konu: pytest test paketi (8 test) ve GitHub Actions CI iş akışı eklendi.
- Durum: ✅ Tüm testler geçiyor.

**Sıradaki iş:** GitHub'da `Log-Bruteforce-Detector` adıyla repo aç, git init + push.

---

## 2026-08-20 — İlk sürüm oluşturuldu
- Konu: SSH brute-force tespit scripti + örnek log + örnek rapor hazırlandı.
- Durum: ✅ Çalışıyor, test edildi.

**Sıradaki iş:** GitHub'da `Log-Bruteforce-Detector` adıyla repo aç, git init + push.
