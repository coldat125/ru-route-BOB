#!/usr/bin/env python3
"""Вырезает всё, что относится к России, из geoip.dat/geosite.dat (Loyalsoldier/v2ray-rules-dat).

На выходе: dist/geoip.dat, dist/geosite.dat (только RU-категории, имена сохранены),
плоские списки dist/ru-domains.txt, dist/ru-cidr.txt и dist/manifest.txt.
"""
import base64
import hashlib
import ipaddress
import json
import pathlib
import sys

SRC = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "src")
OUT = pathlib.Path("dist")

# geoip: что идёт напрямую и что через туннель. cloudflare/cloudfront/fastly
# намеренно не в proxy — это общие CDN, по IP там пополам русских сайтов.
GEOIP_DIRECT = {"ru", "private"}
GEOIP_PROXY = {"google", "facebook", "twitter", "netflix", "telegram"}

# geosite: категория берётся, если имя содержит токен "ru" (category-gov-ru,
# category-media-ru-blocked, tld-ru...) ИЛИ >=25% её доменов сидят в русских TLD.
RU_TLD = (".ru", ".su", ".xn--p1ai", ".moscow", ".tatar", ".xn--80adxhks", ".xn--p1acf")
RU_SHARE = 0.25

# Секции-заглушки под TLD: клиентские конфиги ссылаются на geosite:com/net/org,
# а у Loyalsoldier таких секций нет и Xray без них не стартует.
# Каждая = одно правило domain:<tld>, то есть «весь этот TLD».
SYNTH_TLD = ("com", "net", "org")

# правило промахивается — правим руками. Оба списка регистронезависимы.
INCLUDE = {"kaspersky", "rutracker", "drweb", "gismeteo", "ixbt", "2gis", "ucoz", "comssone"}
EXCLUDE = {"coomer", "kemono", "truyen-hentai", "technogym", "category-finance"}

# Секции, которые нужны клиентским конфигам как есть. Xray не стартует, если
# конфиг ссылается на отсутствующую секцию, поэтому они переносятся из апстрима
# целиком, даже если ничего русского в них нет.
KEEP_SITE = {
    "private", "category-ads", "win-spy",
    "google", "google-play", "github", "youtube", "telegram",
    "tiktok", "instagram", "facebook", "twitter", "openai",
}

# Алиасы на сводную direct: этих имён нет ни у Loyalsoldier, ни где-либо ещё,
# но конфиги их просят (DirectSites: geosite:ru, geosite:geolocation-ru).
ALIAS_DIRECT = ("ru", "geolocation-ru")

# Клиентская пара файлов: ровно те две секции, на которые ссылается профиль
# Happ, и ничего больше.
#
# Нужна из-за iOS: туннель там живёт в сетевом расширении с жёстким лимитом
# памяти, и система убивает его без предупреждения — у человека гаснет сам
# тумблер. Полные файлы этот лимит переполняли, причём в основном дублями:
# geosite direct/ru/geolocation-ru — три имени одного списка, geoip ru и direct
# отличаются на 18 приватных подсетей. Замер: 1 405 972 -> 433 770 байт.
#
# geoip берётся из direct, а не из ru: direct = ru + private, а private это
# домашние подсети. Потеряешь их — у человека в туннель уедут роутер, принтер
# и телевизор в своей же локальной сети.
CLIENT_SITE = "ru"
CLIENT_IP = "direct"

# Секция PROXY: что гнать через туннель. Собирается из этих категорий апстрима.
# Правится руками — состав тут вопрос твоей маршрутизации, а не свойство данных.
PROXY_CATS = {
    "category-media-ru-blocked", "category-vpnservices",
    "youtube", "meta", "facebook", "instagram", "whatsapp",
    "twitter", "x", "discord", "signal", "viber", "linkedin",
    "openai", "anthropic", "category-ai-!cn",
    "spotify", "soundcloud", "netflix", "twitch", "patreon",
    "reddit", "medium", "notion", "tiktok", "bbc",
}


def uvarint(b, i):
    r = s = 0
    while True:
        c = b[i]
        i += 1
        r |= (c & 0x7F) << s
        if not c & 0x80:
            return r, i
        s += 7


def put_uvarint(n):
    out = bytearray()
    while n > 0x7F:
        out.append((n & 0x7F) | 0x80)
        n >>= 7
    out.append(n)
    return bytes(out)


def fields(b, i=0):
    """Плоский разбор protobuf-сообщения: [(номер поля, значение), ...]."""
    out = []
    while i < len(b):
        key, i = uvarint(b, i)
        f, wt = key >> 3, key & 7
        if wt == 0:
            v, i = uvarint(b, i)
        elif wt == 2:
            ln, i = uvarint(b, i)
            v = b[i:i + ln]
            i += ln
        elif wt == 5:
            v = b[i:i + 4]
            i += 4
        elif wt == 1:
            v = b[i:i + 8]
            i += 8
        else:
            raise ValueError(f"wire type {wt}")
        out.append((f, v))
    return out


def entries(path):
    """[(code, сырые байты записи, поля записи), ...] — поле 1 списка = одна запись."""
    data = path.read_bytes()
    out = []
    for f, raw in fields(data):
        if f != 1:
            continue
        fs = fields(raw)
        code = next(v for ff, v in fs if ff == 1).decode()
        out.append((code, raw, fs))
    return out


def pack(raws):
    """Обратная сборка списка: каждая запись — поле 1, wire type 2."""
    return b"".join(b"\x0a" + put_uvarint(len(r)) + r for r in raws)


DOM_TYPE = {0: "keyword", 1: "regexp", 2: "domain", 3: "full"}


def domains(fs):
    out = []
    for ff, v in fs:
        if ff != 2:
            continue
        d = fields(v)
        t = next((x for k, x in d if k == 1), 0)
        out.append((DOM_TYPE.get(t, "domain"), next(x for k, x in d if k == 2).decode()))
    return out


def cidrs(fs):
    out = []
    for ff, v in fs:
        if ff != 2:
            continue
        c = fields(v)
        ip = next(x for k, x in c if k == 1)
        plen = next((x for k, x in c if k == 2), 0)
        out.append(f"{ipaddress.ip_address(bytes(ip))}/{plen}")
    return out


TYPE_ID = {v: k for k, v in DOM_TYPE.items()}


def make_site(code, doms):
    """Собирает GeoSite{country_code, domain: [...]} из списка (тип, значение)."""
    body = b""
    for t, v in doms:
        d = b"\x08" + put_uvarint(TYPE_ID[t]) + b"\x12" + put_uvarint(len(v)) + v.encode()
        body += b"\x12" + put_uvarint(len(d)) + d
    return b"\x0a" + put_uvarint(len(code)) + code.upper().encode() + body


def make_geoip(code, raw_cidrs):
    """GeoIP{country_code, cidr: [...]} из уже закодированных CIDR-сообщений."""
    body = b"".join(b"\x12" + put_uvarint(len(c)) + c for c in raw_cidrs)
    return b"\x0a" + put_uvarint(len(code)) + code.upper().encode() + body


def write_lines(path, lines):
    # только LF: иначе сборка на Windows и на runner'е дают разные хеши
    path.write_bytes(("\n".join(lines) + "\n").encode())


def is_ru(code, doms):
    c = code.lower()
    if c in EXCLUDE:
        return False
    if c in INCLUDE or "ru" in c.split("-"):
        return True
    if not doms:
        return False
    hits = sum(1 for _, v in doms if v.endswith(RU_TLD) or v in ("ru", "su"))
    return hits / len(doms) >= RU_SHARE


def main():
    OUT.mkdir(exist_ok=True)
    manifest = []

    ip_keep, cidr_lines, ip_direct, ip_proxy, ip_proxy_lines = [], [], [], [], []
    seen_ip = set()
    for code, raw, fs in entries(SRC / "geoip.dat"):
        c = code.lower()
        seen_ip.add(c)
        if c not in GEOIP_DIRECT | GEOIP_PROXY:
            continue
        raw_nets = [v for f, v in fs if f == 2]      # сырые CIDR — переносим как есть
        ip_keep.append(raw)
        if c in GEOIP_DIRECT:
            ip_direct += raw_nets
            if c == "ru":                            # private в плоский список не мешаем
                cidr_lines += cidrs(fs)
        else:
            ip_proxy += raw_nets
            ip_proxy_lines += cidrs(fs)
        manifest.append(f"geoip:{c}\t{len(raw_nets)}")
    lost = (GEOIP_DIRECT | GEOIP_PROXY) - seen_ip
    if lost:
        sys.exit(f"geoip.dat: нет секций {sorted(lost)} — апстрим изменился?")

    site_keep, dom_lines = [], []
    ru_doms, proxy_doms, seen_site = set(), set(), set()
    passthru = KEEP_SITE | PROXY_CATS
    for code, raw, fs in entries(SRC / "geosite.dat"):
        c = code.lower()
        seen_site.add(c)
        doms = domains(fs)
        if c in PROXY_CATS:
            proxy_doms.update(doms)
        ru = is_ru(code, doms)
        if not (ru or c in passthru):
            continue
        site_keep.append(raw)
        manifest.append(f"geosite:{c}\t{len(doms)}" + ("" if ru else "\t(перенос из апстрима)"))
        if ru:
            dom_lines += [f"{t}:{v}" for t, v in doms]
            ru_doms.update(doms)
    if not ru_doms:
        sys.exit("geosite.dat: не найдено ни одной русской категории — формат изменился?")
    lost = passthru - seen_site
    if lost:
        sys.exit(f"geosite.dat: нет категорий {sorted(lost)} — апстрим изменился?")

    for tld in SYNTH_TLD:
        if tld in seen_site:   # появилась в апстриме — свою не подсовываем
            continue
        site_keep.append(make_site(tld, [("domain", tld)]))
        dom_lines.append(f"domain:{tld}")
        manifest.append(f"geosite:{tld}\t1\t(синтетическая: весь .{tld})")

    # Сводные секции: одно имя на направление. Пересечение вычитаем из direct,
    # чтобы списки не спорили между собой.
    direct_doms = sorted(ru_doms - proxy_doms)
    proxy_sorted = sorted(proxy_doms)
    site_keep.append(make_site("direct", direct_doms))
    site_keep.append(make_site("proxy", proxy_sorted))
    for alias in ALIAS_DIRECT:
        if alias in seen_site:      # появилось в апстриме — своё не подсовываем
            continue
        site_keep.append(make_site(alias, direct_doms))
        manifest.append(f"geosite:{alias}\t{len(direct_doms)}\t(алиас direct)")
    ip_keep.append(make_geoip("direct", ip_direct))
    ip_keep.append(make_geoip("proxy", ip_proxy))
    manifest.append(f"geosite:direct\t{len(direct_doms)}\t(сводная: все русские минус proxy)")
    manifest.append(f"geosite:proxy\t{len(proxy_sorted)}\t(сводная: из {len(PROXY_CATS)} категорий)")
    manifest.append(f"geoip:direct\t{len(ip_direct)}\t(сводная: {', '.join(sorted(GEOIP_DIRECT))})")
    manifest.append(f"geoip:proxy\t{len(ip_proxy)}\t(сводная: {', '.join(sorted(GEOIP_PROXY))})")

    (OUT / "geoip.dat").write_bytes(pack(ip_keep))
    (OUT / "geosite.dat").write_bytes(pack(site_keep))

    # Клиентская пара: те же данные, только без секций, которые нужны ноде.
    # Содержимое не отбирается заново — берутся те же списки, что уехали в
    # полные файлы, поэтому маршрут ни для одного домена не меняется.
    (OUT / "geosite-lite.dat").write_bytes(pack([make_site(CLIENT_SITE, direct_doms)]))
    (OUT / "geoip-lite.dat").write_bytes(pack([make_geoip(CLIENT_IP, ip_direct)]))
    manifest.append(f"geosite-lite:{CLIENT_SITE}\t{len(direct_doms)}\t(для клиентов)")
    manifest.append(f"geoip-lite:{CLIENT_IP}\t{len(ip_direct)}\t(для клиентов)")
    write_lines(OUT / "ru-cidr.txt", sorted(set(cidr_lines)))
    write_lines(OUT / "ru-domains.txt", sorted(set(dom_lines)))
    write_lines(OUT / "direct-domains.txt", [f"{t}:{v}" for t, v in direct_doms])
    write_lines(OUT / "proxy-domains.txt", [f"{t}:{v}" for t, v in proxy_sorted])
    write_lines(OUT / "proxy-cidr.txt", sorted(set(ip_proxy_lines)))
    write_lines(OUT / "manifest.txt", sorted(manifest))

    # детектор изменений: manifest ловит только счётчики, хеши — само содержимое
    sums = "".join(
        f"{hashlib.sha256((OUT / n).read_bytes()).hexdigest()}  {n}\n"
        for n in sorted(p.name for p in OUT.iterdir() if p.name != "sha256sum.txt")
    )
    (OUT / "sha256sum.txt").write_bytes(sums.encode())

    print(f"geoip:   {len(ip_keep)} стран, {len(set(cidr_lines))} подсетей")
    print(f"geosite: {len(site_keep)} категорий, {len(set(dom_lines))} доменов")


def covered(entry, doms, fulls, kws):
    """Лежит ли домен из профиля внутри секции. Порт и `*.` — не часть имени."""
    e = entry.split(":")[0].removeprefix("*.").lower()
    if e in doms or e in fulls:
        return True
    if any(e.endswith("." + d) for d in doms):
        return True
    return any(k in e for k in kws)


def check_profile(path):
    """Сверяет профиль Happ с клиентской парой файлов.

    Ссылка на отсутствующую секцию — не мелочь: Xray с ней не стартует вообще,
    то есть туннель у человека не поднимется, а в панели профиль применяется
    сразу и всем. Поэтому проверка стоит до публикации, а не после жалоб.

    На вход — файл со строкой `happ://routing/add/<base64>` или сам base64.
    """
    raw = pathlib.Path(path).read_text().strip().rsplit("/", 1)[-1]
    prof = json.loads(base64.b64decode(raw))

    site = {c.lower(): domains(fs) for c, _, fs in entries(OUT / "geosite-lite.dat")}
    ip = {c.lower() for c, _, _ in entries(OUT / "geoip-lite.dat")}

    refs = [(k, v) for k in ("DirectSites", "ProxySites", "BlockSites") for v in prof.get(k, [])]
    refs += [(k, v) for k in ("DirectIp", "ProxyIp", "BlockIp") for v in prof.get(k, [])]

    missing, plain = [], []
    for key, value in refs:
        if value.startswith("geosite:"):
            if value.split(":", 1)[1].lower() not in site:
                missing.append(f"{key}: {value}")
        elif value.startswith("geoip:"):
            if value.split(":", 1)[1].lower() not in ip:
                missing.append(f"{key}: {value}")
        elif key.endswith("Sites"):
            plain.append(value)

    doms = {v for t, v in site.get(CLIENT_SITE, []) if t == "domain"}
    fulls = {v for t, v in site.get(CLIENT_SITE, []) if t == "full"}
    kws = [v for t, v in site.get(CLIENT_SITE, []) if t == "keyword"]
    dupes = [d for d in plain if covered(d, doms, fulls, kws)]

    print(f"geosite-lite: {sorted(site)}   geoip-lite: {sorted(ip)}")
    print(f"ссылок в профиле: {len(refs)}, доменов списком: {len(plain)}")
    if dupes:
        print(f"уже внутри geosite:{CLIENT_SITE}, можно убрать из профиля ({len(dupes)}):")
        print("  " + ", ".join(dupes))
    for d in plain:
        if d not in dupes:
            print(f"остаётся в профиле (в файле нет): {d}")
    if missing:
        sys.exit("профиль ссылается на секции, которых в клиентских файлах нет:\n  "
                 + "\n  ".join(missing))
    print("ok: все ссылки профиля есть в файлах")


def demo():
    """Самопроверка кодека и правила отбора."""
    for n in (0, 1, 127, 128, 300, 165625, 2 ** 31):
        assert uvarint(put_uvarint(n), 0)[0] == n, n
    msg = b"\x0a\x02ru"
    assert fields(msg) == [(1, b"ru")]
    assert pack([msg]) == b"\x0a\x04" + msg
    assert is_ru("CATEGORY-MEDIA-RU-BLOCKED", [])
    assert is_ru("TLD-RU", [])
    assert is_ru("YANDEX", [("domain", "yandex.ru"), ("domain", "yandex.com")])
    assert not is_ru("RUST", [("domain", "rust-lang.org")])
    assert not is_ru("KEMONO", [("domain", "kemono.su")])
    assert is_ru("KASPERSKY", [("domain", "kaspersky.com")])
    raw = make_site("com", [("domain", "com")])
    fs = fields(raw)
    assert next(v for f, v in fs if f == 1) == b"COM"
    assert domains(fs) == [("domain", "com")]
    mixed = [("domain", "a.ru"), ("full", "b.ru"), ("keyword", "c"), ("regexp", "d.+")]
    assert domains(fields(make_site("direct", mixed))) == mixed
    net = b"\x0a\x04\x0a\x00\x00\x00\x10\x08"          # 10.0.0.0/8
    assert cidrs(fields(make_geoip("proxy", [net]))) == ["10.0.0.0/8"]
    assert fields(pack([raw]))[0][1] == raw
    # covered: на нём держится ответ «этот домен из профиля уже в файле, можно
    # убрать». Ошибётся в сторону «уже есть» — домен уедет в туннель молча.
    assert covered("www.sber.ru", {"sber.ru"}, set(), [])          # родитель
    assert covered("wildberries.ru:443", {"wildberries.ru"}, set(), [])  # порт не мешает
    assert covered("*.vk.com", {"vk.com"}, set(), [])              # звёздочка не мешает
    assert covered("a.example.net", set(), set(), ["example"])     # keyword
    assert not covered("alfa.bank", {"alfabank.ru"}, set(), [])    # другой домен
    assert not covered("ozoncdn.net", {"ozon.ru"}, set(), [])      # не поддомен
    print("ok")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        demo()
    elif "--check-profile" in sys.argv:
        check_profile(sys.argv[sys.argv.index("--check-profile") + 1])
    else:
        main()
