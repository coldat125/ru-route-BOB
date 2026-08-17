#!/usr/bin/env python3
"""Вырезает всё, что относится к России, из geoip.dat/geosite.dat (Loyalsoldier/v2ray-rules-dat).

На выходе: dist/geoip.dat, dist/geosite.dat (только RU-категории, имена сохранены),
плоские списки dist/ru-domains.txt, dist/ru-cidr.txt и dist/manifest.txt.
"""
import hashlib
import ipaddress
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
    for code, raw, fs in entries(SRC / "geosite.dat"):
        c = code.lower()
        seen_site.add(c)
        doms = domains(fs)
        if c in PROXY_CATS:
            proxy_doms.update(doms)
        if not is_ru(code, doms):
            continue
        site_keep.append(raw)
        dom_lines += [f"{t}:{v}" for t, v in doms]
        ru_doms.update(doms)
        manifest.append(f"geosite:{c}\t{len(doms)}")
    if not site_keep:
        sys.exit("geosite.dat: не найдено ни одной русской категории — формат изменился?")
    lost = PROXY_CATS - seen_site
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
    ip_keep.append(make_geoip("direct", ip_direct))
    ip_keep.append(make_geoip("proxy", ip_proxy))
    manifest.append(f"geosite:direct\t{len(direct_doms)}\t(сводная: все русские минус proxy)")
    manifest.append(f"geosite:proxy\t{len(proxy_sorted)}\t(сводная: из {len(PROXY_CATS)} категорий)")
    manifest.append(f"geoip:direct\t{len(ip_direct)}\t(сводная: {', '.join(sorted(GEOIP_DIRECT))})")
    manifest.append(f"geoip:proxy\t{len(ip_proxy)}\t(сводная: {', '.join(sorted(GEOIP_PROXY))})")

    (OUT / "geoip.dat").write_bytes(pack(ip_keep))
    (OUT / "geosite.dat").write_bytes(pack(site_keep))
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
    print("ok")


if __name__ == "__main__":
    demo() if "--selftest" in sys.argv else main()
