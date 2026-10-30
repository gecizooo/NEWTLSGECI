# TLS13-PQ — tiszta Python referencia

Ez a mappa **csak Python**. Nincs Go, nincs pip-függőség, nincs build lépés.
Python 3.10+ kell, semmi más.

A mögötte lévő specifikáció a `../tls13-pq/draft-tls13-pq-00.md`.

## Futtatás

```bash
cd /home/mart/tls13pq

python3 demo.py                     # teljes 0-RTT bemutató
python3 -m tls13pq validate example.json
python3 -m unittest                 # 40 teszt
```

Telepítés nélkül, a mappából. Ha mégis kell console script:

```bash
pip install -e .
tls13pq demo
```

## Mit mutat a demo

```
1. első 0-RTT flight          -> S_EARLY -> S_COMMIT -> S_OPEN, 1 hatás
2. bájtazonos replay          -> a szűrő elutasítja, 1-RTT-re esik vissza
3. replay, szűrő megkerülve   -> a commit store dedupál, a hatás továbbra is 1
4. lejárt ticket              -> elutasítva, 1-RTT
5. legacy kliens (nincs guard)-> elutasítva, 1-RTT
```

A 3. lépés a lényeg: **a commit store önmagában is megakadályozza a duplikált
mellékhatást**, akkor is, ha a replay-szűrő hibázik. Ez a spec 5.9-es
Tétele 2, tesztelve.

## Mappaszerkezet

```
tls13pq/
├── demo.py                  # python3 demo.py
├── example.json             # referencia konfiguráció
├── pyproject.toml           # opcionális, függőség nélkül
├── tls13pq/
│   ├── __init__.py
│   ├── __main__.py          # python3 -m tls13pq
│   ├── config.py            # séma + validáció (Go-val azonos szabályok)
│   ├── early_data.py        # SUT-CD: filter + commit store
│   ├── padding.py           # ECH padding osztályok, szegmensszám
│   ├── handshake.py         # szerver oldali állapotgép szimulátor
│   └── demo.py              # a bemutató tartalma
└── tests/
    ├── test_config.py       # 16 teszt
    ├── test_early_data.py   # 12 teszt
    └── test_handshake.py    # 12 teszt
```

## Amit érdemes tudni

- **Nincs `pydantic`.** A JSON dekóder saját, szigorú: ismeretlen mező =
  `ConfigError`, hogy egy elgépelt `failmode` ne csússzon át csendben.
- **`FailMode` egyetlen értéke `closed`.** Fail-open nem reprezentálható.
- **Nevek, nem codepointok.** A config `"X25519MLKEM768"`-ot ír, nem
  `0x11ec`-et; a decimális elgépelés biztonsági hiba, a név elgépelése
  betöltési hiba.
- **Időtartamok** Go-stílusban: `"10s"`, `"24h"`, `"1m30s"`; szám esetén
  másodperc.
- A `padding.py` szándékosan közelít; a valós wire-méreteket mérni kell.

## Tesztek

```bash
python3 -m unittest -v
# Ran 40 tests ... OK
```

A tesztek lefedik a validációs szabályokat, a replay/dedup viselkedést, az
ECH padding osztályokat, és a szimulátor állapotátmeneteit.
