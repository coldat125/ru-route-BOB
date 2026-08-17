# ru-route-BOB

Только российская часть [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat).
Обновляется автоматически раз в сутки (02:30 UTC).

| Файл | Что внутри |
|---|---|
| `dist/geoip.dat` | `geoip:ru` (~25 тыс. подсетей) + `geoip:private` |
| `dist/geosite.dat` | ~83 категории: русские: `category-ru`, `category-gov-ru`, `category-bank-ru`, `tld-ru`, `yandex`, `vk`, `sber`, `ozon`, `wildberries`, … |
| `dist/ru-domains.txt` | те же домены плоским списком (`domain:`/`full:`/`keyword:`/`regexp:`) |
| `dist/ru-cidr.txt` | подсети RU плоским списком (без `private`) |
| `dist/manifest.txt` | список категорий и количество записей — по его диффу видно, что изменилось |
| `dist/sha256sum.txt` | контрольные суммы |

10 МБ + 17 МБ исходников ужимаются до ~480 КБ.

## Использование (Xray / v2ray)

Положить `dist/*.dat` рядом с бинарником (или в `XRAY_LOCATION_ASSET`) и ссылаться как обычно:

```json
{
  "routing": {
    "rules": [
      { "type": "field", "domain": ["geosite:category-ru", "geosite:tld-ru"], "outboundTag": "direct" },
      { "type": "field", "ip": ["geoip:ru", "geoip:private"], "outboundTag": "direct" }
    ]
  }
}
```

Файлы выкладываются в [релизы](https://github.com/coldat125/ru-route-BOB/releases) (тег — дата сборки),
в самом репозитории лежат только манифест и контрольные суммы. Постоянные ссылки на свежую сборку:

```
https://github.com/coldat125/ru-route-BOB/releases/latest/download/geoip.dat
https://github.com/coldat125/ru-route-BOB/releases/latest/download/geosite.dat
https://github.com/coldat125/ru-route-BOB/releases/latest/download/ru-domains.txt
https://github.com/coldat125/ru-route-BOB/releases/latest/download/ru-cidr.txt
```

## Как отбираются категории

`build.py` берёт категорию, если её имя содержит токен `ru` (`category-media-ru-blocked`,
`tld-ru`) **или** ≥25 % её доменов сидят в `.ru/.su/.рф/.moscow/.tatar`.
Правило промахивается на брендах без русского домена и на чужих сайтах в `.su` —
для них в начале `build.py` есть два коротких списка `INCLUDE` / `EXCLUDE`, правятся руками.

Дополнительно добавляются синтетические секции `geosite:com`, `geosite:net`, `geosite:org` —
по одному правилу `domain:<tld>`, то есть «весь этот TLD». У Loyalsoldier таких секций нет,
а клиентские конфиги на них ссылаются, и Xray без них не стартует вообще
(«отсутствует секция COM в подключенном файле geosite.dat»). Список — `SYNTH_TLD` в `build.py`;
если секция с таким именем появится в апстриме, своя не подставляется.

Локальная сборка:

```bash
curl -fsSLO --output-dir src https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
python3 build.py --selftest && python3 build.py
```
