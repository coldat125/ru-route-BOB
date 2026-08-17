#!/usr/bin/env python3
"""Вырезает всё, что относится к России, из geoip.dat/geosite.dat (Loyalsoldier/v2ray-rules-dat).

На выходе: dist/geoip.dat, dist/geosite.dat (только RU-категории, имена сохранены),
плоские списки dist/ru-domains.txt, dist/ru-cidr.txt и dist/manifest.txt.
"""
import ipaddress
import pathlib
import sys

SRC = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "src")
OUT = pathlib.Path("dist")

# geoip: коды стран, которые забираем
GEOIP_CODES = {"ru", "private"}

# geosite: категория берётся, если имя содержит токен "ru" (category-gov-ru,
# category-media-ru-blocked, tld-ru...) ИЛИ >=25% её доменов сидят в русских TLD.
RU_TLD = (".ru", ".su", ".xn--p1ai", ".moscow", ".tatar", ".xn--80adxhks", ".xn--p1acf")
RU_SHARE = 0.25

# правило промахивается — правим руками. Оба списка регистронезависимы.
INCLUDE = {"kaspersky", "rutracker", "drweb", "gismeteo", "ixbt", "2gis", "ucoz", "comssone"}
EXCLUDE = {"coomer", "kemono", "truyen-hentai", "technogym", "category-finance"}


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

    ip_keep, cidr_lines = [], []
    for code, raw, fs in entries(SRC / "geoip.dat"):
        if code.lower() not in GEOIP_CODES:
            continue
        nets = cidrs(fs)
        ip_keep.append(raw)
        if code.lower() == "ru":  # private в плоский список не мешаем
            cidr_lines += nets
        manifest.append(f"geoip:{code.lower()}\t{len(nets)}")
    if len(ip_keep) != len(GEOIP_CODES):
        sys.exit(f"geoip.dat: нашлось {len(ip_keep)} из {len(GEOIP_CODES)} нужных кодов — формат вышестоящего файла изменился?")

    site_keep, dom_lines = [], []
    for code, raw, fs in entries(SRC / "geosite.dat"):
        doms = domains(fs)
        if not is_ru(code, doms):
            continue
        site_keep.append(raw)
        dom_lines += [f"{t}:{v}" for t, v in doms]
        manifest.append(f"geosite:{code.lower()}\t{len(doms)}")
    if not site_keep:
        sys.exit("geosite.dat: не найдено ни одной русской категории — формат изменился?")

    (OUT / "geoip.dat").write_bytes(pack(ip_keep))
    (OUT / "geosite.dat").write_bytes(pack(site_keep))
    (OUT / "ru-cidr.txt").write_text("\n".join(sorted(set(cidr_lines))) + "\n")
    (OUT / "ru-domains.txt").write_text("\n".join(sorted(set(dom_lines))) + "\n")
    (OUT / "manifest.txt").write_text("\n".join(sorted(manifest)) + "\n")

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
    print("ok")


if __name__ == "__main__":
    demo() if "--selftest" in sys.argv else main()
