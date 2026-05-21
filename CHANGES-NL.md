# Patches voor node-red-contrib-loxone (Loxone Gen2 / firmware ≥ 10.2 / ≥ 14.x)

## Samenvatting

`node-red-contrib-loxone` 0.10.13 zelf is OK, maar de onderliggende
bibliotheek `node-lox-ws-api` (gepind op `github:codm/node-lox-ws-api#0.4.5-bugfix4`)
bevat **een fundamentele bug in de HMAC-key-decodering** en gebruikt
**een endpoint dat op moderne miniservers (>= 10.2) niet meer betrouwbaar werkt**.

Resultaat op nieuwe firmware: HTTP 401 / `auth_failed` direct na `getkey2`.

De gepatchte bibliotheek is **vendored** als bundled dependency in
`./node_modules/node-lox-ws-api/` binnen deze plugin (was eerder sibling
`../node-lox-ws-api/`). De `package.json` declareert dit als:

```json
"dependencies": { "node-lox-ws-api": "0.4.6-iot" },
"bundledDependencies": ["node-lox-ws-api"]
```

Bij `npm pack` / `npm install` neemt npm de subfolder automatisch mee
(geen `file:` indirectie nodig).

Na `npm install` in `node-red-contrib-loxone/` (of een symlink in
`~/.node-red/node_modules/`) pakt Node-RED automatisch de patches op.

---

## Referentie-implementatie + credits

De fixes zijn 1-op-1 afgeleid van [`testscripts/loxone_ws_auth_test4.py`](./testscripts/loxone_ws_auth_test4.py),
dat een directe poort is van **[PyLoxone](https://github.com/JoDehli/PyLoxone)** door
[Jo Dehli](https://github.com/JoDehli) — specifiek
`custom_components/loxone/pyloxone_api/connection.py`. Regelnummers staan
in de Python-broncode bij iedere stap, zodat je kan terugkijken naar de
originele PyLoxone-implementatie.

Die Python-flow werkt aantoonbaar tegen Loxone Miniservers met firmware
≥ 10.2 (getest op FW 14.x). Zonder die werkende referentie-implementatie
was het lokaliseren van de drie node-lox-ws-api bugs aanzienlijk lastiger
geweest — dank aan Jo Dehli en de PyLoxone-contributors.

PyLoxone is gelicenseerd onder de **Apache License 2.0**. Het gebruikte
script in `testscripts/` blijft een Apache-2.0-derivaat (zie
[`testscripts/LICENSE-PyLoxone`](./testscripts/LICENSE-PyLoxone)) en
vermeldt de wijzigingen t.o.v. upstream in zijn header. De rest van deze
plugin (node-red-contrib-loxone zelf en de vendored node-lox-ws-api)
blijft MIT zoals codmpm's origineel.

---

## BUG 1 — HMAC-key wordt corrupt door UTF-8-herinterpretatie

**Plekken:**
- `lib/Auth/Hash.js`        (legacy)
- `lib/Auth/AES-256-CBC.js` (mid-tier)
- `lib/Auth/Token-Enc.js`   ×2 (modern: `getkey2` + `refreshtoken`)

**Oude code:**
```js
var key = new Buffer(loxone_message.value, 'hex').toString('utf8');
var hmac = crypto.createHmac('sha1', key);
```

**Probleem:** `value` is een hexadecimale string die een willekeurig random
32-byte key voorstelt. `new Buffer(value, 'hex')` decodeert dat goed naar
binaire bytes, **maar** `.toString('utf8')` interpreteert die bytes
vervolgens als UTF-8 tekst. Vrijwel iedere random-key bevat byte-sequenties
die geen geldige UTF-8 vormen. Die worden door Node vervangen door het
Unicode-replacement-karakter `U+FFFD` (3 bytes: `EF BF BD`). De resulterende
"key" is dus structureel anders dan de echte key — de HMAC die ermee wordt
berekend klopt niet met wat de miniserver verwacht.

**Patch:**
```js
var key = Buffer.from(loxone_message.value, 'hex');   // raw bytes, klaar.
var hmac = crypto.createHmac('sha1', key);
```

**Vergelijking met PyLoxone (`connection.py` r420):**
```python
digester = HMAC.new(bytes.fromhex(key_hex), hmac_input.encode("utf-8"), hash_module)
```
Geen tussenstap, geen UTF-8 decode — exact wat de Loxone-doc voorschrijft.

> Waarom werkte dit ooit? Op miniservers met oudere firmware waren key/salts
> kleiner (16B) en bevatten relatief vaker UTF-8-veilige bytes. Sinds de
> overstap naar 32-byte AES-keys + SHA-256 hit je de bug bijna altijd.

---

## BUG 2 — `gettoken` is deprecated; gebruik `getjwt` op MS ≥ 10.2

**Plek:** `lib/Auth/Token-Enc.js` r150

**Oude code:**
```js
that._connection.send(that._enc_command('jdev/sys/gettoken/' + hash + '/' + that._username
    + '/2/edfc5f9a-df3f-4cad-9dddcdc42c732be2/nodeloxwsapi'));
```

**Probleem:** Loxone vraagt vanaf Miniserver-firmware 10.2 om
`jdev/sys/getjwt/...` (JSON Web Token i.p.v. de oude token-struct).
Op recente firmware (14+) accepteert `gettoken` vaak helemaal niet meer.

**Patch (samen met FIX in API.js die de versie doorgeeft):**
```js
var ver = that._api._ms_version || [0, 0];
var use_jwt = (ver[0] > 10) || (ver[0] === 10 && ver[1] >= 2);
var token_cmd = use_jwt ? 'jdev/sys/getjwt/' : 'jdev/sys/gettoken/';
that._connection.send(that._enc_command(token_cmd + hash + '/' + that._username
    + '/2/edfc5f9a-df3f-4cad-9dddcdc42c732be2/nodeloxwsapi'));
```

**API.js `perform_version_check`:** registreert nu de versie:
```js
that._ms_version = version.map(function (v) { return parseInt(v, 10); });
```

**Vergelijking met PyLoxone (`connection.py`):**
```python
CMD_REQUEST_TOKEN          = "jdev/sys/gettoken"     # MS < 10.2
CMD_REQUEST_TOKEN_JSON_WEB = "jdev/sys/getjwt"       # MS >= 10.2
...
cmd_token = CMD_REQUEST_TOKEN_JSON_WEB if miniserver_version >= [10, 2] else CMD_REQUEST_TOKEN
```

---

## BUG 3 — Command-chain regex matcht alleen `gettoken`

**Plek:** `lib/Auth/Token-Enc.js` `_register_gettoken_response`

**Oude code:**
```js
'control': /^j?dev\/sys\/gettoken\//,
```

**Probleem:** zodra we (BUG 2) op `getjwt` overschakelen, herkent de
chain de respons niet meer en wordt `authorized` nooit gefired → time-out.

**Patch:**
```js
'control': /^j?dev\/sys\/(gettoken|getjwt)\//,
```

---

## Wat NIET gepatcht is, maar wel opgemerkt

| Onderdeel | Verschil JS vs Python | Impact |
|---|---|---|
| `CLIENT_UUID` | JS: `…b82` vs PY: `…be2` (typo) | Geen auth-impact; alleen token-administratie op de MS |
| `CLIENT_INFO` | JS: `nodeloxwsapi` vs PY: `pyloxone_api` | Geen impact |
| WS-subprotocol | JS: geen, PY: optioneel `remotecontrol` | Beide werken, miniserver is tolerant |
| Salt-hergebruik | JS: tot 200x of 30s; PY: nieuwe per request | Geen impact, beide schema's zijn doc-conform |
| `new Buffer()` (deprecated) | overal in lib | Werkt nog wel; warnings vanaf Node 10. Niet aangeraakt om de diff klein te houden |
| `setAutoPadding(false)` + null-strip | identiek in beide | OK |

---

## Test-procedure

Installeer de plugin direct vanaf deze fork:

```bash
cd ~/.node-red                                    # of $env:USERPROFILE\.node-red op Windows
npm install github:iot-experimenter/node-red-contrib-loxone
```

Herstart Node-RED. Verwacht in de log:

- `Miniserver connected (...) using Token-Enc`
- `got structure file <timestamp>`

Loopt het mis met `auth_failed`, vergelijk dan de hash uit de JS-log met
de hash die [`testscripts/loxone_ws_auth_test4.py`](./testscripts/loxone_ws_auth_test4.py)
op dezelfde miniserver berekent — die moeten identiek zijn.

Het Python-script is een directe poort van PyLoxone's `connection.py` en
werkt aantoonbaar tegen FW 14.x. Vul `HOST`, `USERNAME`, `PASSWORD`
bovenaan in en draai:

```bash
pip install aiohttp websockets pycryptodome
python testscripts/loxone_ws_auth_test4.py
```

---

## Files gewijzigd

| Bestand | Wijziging |
|---|---|
| `./node_modules/node-lox-ws-api/lib/Auth/Hash.js` | BUG 1 |
| `./node_modules/node-lox-ws-api/lib/Auth/AES-256-CBC.js` | BUG 1 |
| `./node_modules/node-lox-ws-api/lib/Auth/Token-Enc.js` | BUG 1 (×2) + BUG 2 + BUG 3 |
| `./node_modules/node-lox-ws-api/lib/API.js` | versie-detectie t.b.v. BUG 2 |
| `package.json` (deze map) | dependency naar lokale gepatchte lib |
