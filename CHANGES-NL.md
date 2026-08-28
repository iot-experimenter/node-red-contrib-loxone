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

## Referentie-implementatie

De fixes zijn 1-op-1 afgeleid van `testscripts/loxone_ws_auth_test4.py`, dat
een directe poort is van [PyLoxone-master](https://github.com/JoDehli/PyLoxone)
`connection.py` (regelnummers staan in de Python-broncode bij iedere stap).
Die Python-flow werkt aantoonbaar wél tegen onze miniserver (192.168.1.27, FW 14.x).

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

## PATCH 4 (0.10.15-iot / lib 0.4.7-iot) — HTTPS/WSS: firmware sluit poort 80

**Aanleiding (2026-08):** na de Loxone-upgrade (firmware 17.1.7.27) is poort 80
volledig dicht; de miniserver is alleen nog via HTTPS/poort 443 bereikbaar
(`httpsStatus:1` in `jdev/cfg/apiKey`). De lib had `http://` en `ws://`
hardcoded op vier plekken.

**Plekken:**
- `lib/API.js` — constructor + `perform_version_check` (`jdev/cfg/api`)
- `lib/Connection.js` — websocket-URL + `WebSocketClient`-config
- `lib/Auth/Token-Enc.js` — `_get_public_key` (`jdev/sys/getPublicKey`)
- `loxone/loxone.js` + `loxone/loxone.html` (plugin) — secure-vlag in confignode

**Mechanisme:** de plugin geeft de host nu door als
`https://<host>:<port>` wanneer de nieuwe checkbox *Use HTTPS/WSS* aanstaat
(default aan, default poort 443). `API.js` herkent de prefix, stript hem en zet
`this._secure`; daarop volgen `https.get(...)` voor de twee HTTP-calls en
`wss://` + `tlsOptions` voor de websocket.

**Certificaat:** validatie staat in secure-modus uit
(`rejectUnauthorized: false`): het Miniserver-certificaat is uitgegeven op
`{snr}.dns.loxonecloud.com` en matcht per definitie geen lokaal IP. Dit is
dezelfde afweging die PyLoxone/Home Assistant maken voor lokale verbindingen.

**Bewust niet gepatcht:**
- `lib/Auth/AES-256-CBC.js` blijft HTTP-only — legacy-auth voor MS ≤ v8;
  op firmware ≥ 9 kiest `API.js` altijd Token-Enc.
- Editor-helper `struct-changed` (basic auth op `/data/LoxAPP3.json`) volgt de
  secure-vlag, maar firmware 17 weigert basic auth sowieso (401). De runtime
  haalt de structuur via de geauthenticeerde websocket — dat pad werkt.

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

```powershell
# 1. Installeer de gepatchte plugin in je Node-RED user dir
cd $env:USERPROFILE\.node-red
npm install C:\Users\johan\Documents\python\loxone-websockettest\node-red-contrib-loxone

# 2. Restart Node-RED en bekijk de log
# Verwacht: "Miniserver connected (...) using Token-Enc"
#           "got structure file <timestamp>"
```

Loopt het mis met `auth_failed`, vergelijk dan de hash uit de JS-log met
de hash die `loxone_ws_auth_test4.py` op dezelfde miniserver berekent —
die moeten nu identiek zijn.

---

## Files gewijzigd

| Bestand | Wijziging |
|---|---|
| `./node_modules/node-lox-ws-api/lib/Auth/Hash.js` | BUG 1 |
| `./node_modules/node-lox-ws-api/lib/Auth/AES-256-CBC.js` | BUG 1 |
| `./node_modules/node-lox-ws-api/lib/Auth/Token-Enc.js` | BUG 1 (×2) + BUG 2 + BUG 3 + PATCH 4 |
| `./node_modules/node-lox-ws-api/lib/API.js` | versie-detectie t.b.v. BUG 2 + PATCH 4 |
| `./node_modules/node-lox-ws-api/lib/Connection.js` | PATCH 4 (wss:// + tlsOptions) |
| `./loxone/loxone.js` | PATCH 4 (secure-vlag → https://-prefix; editor-helper) |
| `./loxone/loxone.html` | PATCH 4 (checkbox Use HTTPS/WSS, default poort 443) |
| `package.json` (deze map) | dependency naar lokale gepatchte lib |
