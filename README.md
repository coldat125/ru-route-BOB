# ru-route-BOB

Только российская часть [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat).
Обновляется автоматически раз в сутки (02:30 UTC).

Два направления лежат в одних и тех же двух файлах — клиент грузит только `geoip.dat` + `geosite.dat`:

| Секция | Записей | Что это |
|---|---|---|
| `geosite:direct` | 1937 | всё русское, **минус** то, что попало в `proxy` |
| `geosite:proxy` | 1363 | что гнать через туннель: заблокированные медиа, YouTube, Meta, X, Discord, OpenAI, … |
| `geoip:direct` | 25 179 | `ru` + `private` |
| `geoip:proxy` | 8 170 | диапазоны Google, Facebook, Twitter, Netflix, Telegram |

Гранулярные категории тоже на месте, если нужно точечно: `category-ru`, `category-gov-ru`,
`category-bank-ru`, `tld-ru`, `yandex`, `vk`, `sber`, `ozon`, `wildberries`, `geoip:ru`, `geoip:private`, …
(полный список — `manifest.txt`).

| Файл | Что внутри |
|---|---|
| `dist/geoip.dat` | 9 секций: `direct`, `proxy`, `ru`, `private`, `google`, `facebook`, `twitter`, `netflix`, `telegram` |
| `dist/geosite.dat` | 85 секций: `direct`, `proxy`, ~80 русских, `com`/`net`/`org` |
| `dist/direct-domains.txt` | секция `direct` плоским списком (`domain:`/`full:`/`keyword:`/`regexp:`) |
| `dist/proxy-domains.txt` | секция `proxy` плоским списком |
| `dist/ru-cidr.txt` | подсети RU (без `private`) |
| `dist/proxy-cidr.txt` | подсети из `geoip:proxy` |
| `dist/ru-domains.txt` | все русские домены, до вычитания `proxy` |
| `dist/manifest.txt` | секции и количество записей — по его диффу видно, что изменилось |
| `dist/sha256sum.txt` | контрольные суммы |

## Использование (Xray / v2ray)

Положить `dist/*.dat` рядом с бинарником (или в `XRAY_LOCATION_ASSET`):

```json
{
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      { "type": "field", "domain": ["geosite:proxy"],  "outboundTag": "proxy"  },
      { "type": "field", "domain": ["geosite:direct"], "outboundTag": "direct" },
      { "type": "field", "ip":     ["geoip:proxy"],    "outboundTag": "proxy"  },
      { "type": "field", "ip":     ["geoip:direct"],   "outboundTag": "direct" }
    ]
  }
}
```

**Порядок правил важен.** `direct` содержит `domain:ru`, то есть всю зону `.ru` целиком,
и заблокированное русское медиа в `.ru` тоже под него попадает. Правило `proxy` должно стоять
выше — Xray берёт первое совпавшее. Из значений `direct` пересечение с `proxy` уже вычтено,
но от совпадения по catch-all `domain:ru` спасает только порядок.

Файлы выкладываются в [релизы](https://github.com/coldat125/ru-route-BOB/releases) (тег — дата сборки),
в самом репозитории лежат только манифест и контрольные суммы. Постоянные ссылки на свежую сборку:

```
https://github.com/coldat125/ru-route-BOB/releases/latest/download/geoip.dat
https://github.com/coldat125/ru-route-BOB/releases/latest/download/geosite.dat
https://github.com/coldat125/ru-route-BOB/releases/latest/download/direct-domains.txt
https://github.com/coldat125/ru-route-BOB/releases/latest/download/proxy-domains.txt
https://github.com/coldat125/ru-route-BOB/releases/latest/download/ru-cidr.txt
https://github.com/coldat125/ru-route-BOB/releases/latest/download/proxy-cidr.txt
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

Состав `proxy` — это решение о маршрутизации, а не свойство данных, поэтому он задан явными
списками в начале `build.py`: `PROXY_CATS` (26 категорий geosite) и `GEOIP_PROXY`.
`cloudflare`, `cloudfront` и `fastly` намеренно не в `geoip:proxy` — это общие CDN, по IP
там пополам русских сайтов, и они уехали бы в туннель заодно. Если какая-то из перечисленных
секций исчезнет из апстрима, сборка падает с её именем, а не выкладывает молча урезанный список.

Локальная сборка:

```bash
curl -fsSLO --output-dir src https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat
python3 build.py --selftest && python3 build.py
```
