#!/usr/bin/env python3
"""Профиль роутинга Happ со свежим LastUpdated + deeplink happ://routing/add.

Happ перекачивает geo-файлы, только если lastUpdatedDate в профиле больше того,
что уже лежит на устройстве. Поэтому таймстамп штампуется здесь, при публикации:
дата растёт ровно тогда, когда изменились сами данные, и обновление подписки
тянет за собой перекачку. Запускать после build.py.
"""
import base64
import json
import pathlib
import time

OUT = pathlib.Path("dist")
profile = json.loads(pathlib.Path("happ-profile.json").read_text(encoding="utf-8"))
profile["LastUpdated"] = str(int(time.time()))

OUT.mkdir(exist_ok=True)
body = json.dumps(profile, ensure_ascii=False, separators=(",", ":"))
link = "happ://routing/add/" + base64.b64encode(body.encode()).decode()
(OUT / "happ-routing.json").write_bytes((json.dumps(profile, ensure_ascii=False, indent=2) + "\n").encode())
(OUT / "happ-routing.txt").write_bytes((link + "\n").encode())

assert json.loads(base64.b64decode(link.split("/")[-1])) == profile, "ссылка не декодируется обратно"
print(f"happ-routing.txt: {len(link)} символов, LastUpdated={profile['LastUpdated']}")
