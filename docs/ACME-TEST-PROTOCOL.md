# ACME testprotokoll – SUCM

| Fält | Värde |
|------|-------|
| System under test | SUCM **v0.12.0** (ACME-server, `/acme/...`) |
| Miljö | sucm-test (`https://sucm-test.it.su.se/acme/directory`) |
| Testverktyg | `sucm-acme-tester` (se `git log`) |
| Körd från | haak0644.it.su.se som haak0644 |
| Testkonto | Account Id 10015 (testkonto, ska deaktiveras efter test) |
| Testdomän | `acmetest-haak0644.it.su.se` |
| CA-plugin (`[ACME]`) | `________` (bekräfta att det är CA:ns testmiljö) |
| Datum / testare | `________` |

Referens: RFC 8555 (ACME), RFC 8738 (IP, ej i scope), RFC 9773 (ARI, ej i scope).

## Syfte och upplägg
**Syfte:** verifiera funktionellt att SUCM:s ACME-server (`/acme/...`) uppfyller RFC 8555 i så stor utsträckning att en
standardklient (certbot) kan **få ut ett certifikat**. Full konformitet är sekundärt, därför är testerna indelade i nivåer
och nivå 1 är det som avgör om ACME-funktionen är användbar.

**Uppläggning:**
- Black-box: testverktyget talar bara HTTP/JWS mot servern och importerar ingen SUCM-kod.
- Två klienter: en egen minimal ACME-klient (kan skicka avsiktligt felaktiga requests i nivå 2–3) och riktiga certbot (e2e-smoke).
- Körs från haak0644.it.su.se som användaren haak0644 (ej root). Python-testerna använder systemets Python; certbot-skriptet
  använder egna config-kataloger och ignorerar en befintlig (trasig) certbot-konfiguration på maskinen.
- Konton skapas manuellt i portalen (`/acme-accounts/`), aktiveras av admin (grupp `it-produktion-infra-imdb`) och får
  en domän på allow-listen. EAB-uppgifterna är engångsuppgifter för testkonton och ska deaktiveras efter testerna.
- Nycklar och uppgifter ligger **utanför repot**, i `~/.config/sucm-acme-tester/` på testmaskinen (chmod 700/600).
- Servern binder ett EAB-kid till den första kontonyckeln den ser. Testverktyget sparar därför sin kontonyckel, och
  certbot sin config-dir, så att samma konto kan användas vid omkörning.
- Servern är trust-baserad (ingen riktig domänvalidering): authorizations skapas redan `valid` och certbot går direkt till finalize.
  Wildcard-certifikat stöds inte, avsiktligt.

## Körlogg 2026-10-23
| Tid | Händelse | Utfall |
|-----|----------|--------|
| 10:29 | Konto 10015 begärt, EAB-uppgifter mottagna | Konto `pending` |
| 10:30 | Första körning, konto ej aktiverat | `newAccount` → `unauthorized: not yet activated` (L2-11, OK). EAB-signaturen godkändes redan här. |
| 10:32 | Konto aktiverat (TOPdesk 123), domän tillagd. Körning 1 | Protokollnivån PASS; kontot bands till testarens första (osparade) nyckel. |
| 10:33 | Körning 2 med ny slumpnyckel | `EAB credential is already bound to a different account key` (L3-12, OK, men visade en bugg i testaren: nyckeln sparades inte). Konto 10015 därmed förbrukat. |
| 10:36 | Testaren ändrad: kontonyckeln sparas i state-katalogen | Fix |
| 10:38 | Nytt konto, ny EAB, aktiverat | `newAccount`, `newOrder`, authz PASS |
| 10:39 | Finalize | **FAIL** `serverInternal`: `[ACME] ca_plugin_name / secret_path missing from config` (se F1) |
| 10:53 | `[ACME]` tillagd **temporärt för test** direkt på cert-test-app02 i `/local/cert-app/conf/sucm_conf.ini` (`Harica_EAB`, `SUCMTEST/test/ssl/`, tom notify_group_id). Backup: `sucm_conf.ini.bak-acmetest`. Appen omladdad via `touch sucm.wsgi`. | Skrivs över vid nästa salt-highstate (F2). |
| 10:56 | Full nivå 1 (`pytest -m level1`) | **8/8 PASS**, ett cert utfärdat för `acmetest-haak0644.it.su.se` |

## Fynd under test
| # | Fynd | Orsak | Åtgärd |
|---|------|-------|--------|
| F1 | `finalize` ger HTTP 500 `ACME issuance is not configured on this server` | Commit `9b3a26a` ("Refactoring and hardening") flyttade `ca_plugin_name`/`secret_path` från hårdkodade värden (`Harica_EAB`, `SUCMTEST/test/ssl/`) till `[ACME]` i `sucm_conf.ini`. Sektionen saknas på sucm-test, så utfärdande fail-closed. Förväntat beteende, men blockerar nivå 1. | Lägg till `[ACME]` i konfigen **via salt** (se F2) |
| F2 | Config på sucm-test hanteras av salt (`su-salt-states-services-cert`, `services/cert/app/init.sls`, `file.managed` av `/local/cert-app/conf/sucm_conf.ini`). En manuell ändring på servern **skrivs över** vid nästa highstate/redeploy. | Mallen `files/local/cert-app/conf/sucm_conf.ini` saknar `[ACME]` | Lägg `[ACME]` i mallen (värden via `settings.sls`/pillar, olika för test och prod) |
| F3 | Servern har en `[HARICA_ACME]`-sektion som inte finns i den lokala saltmallen | Salt-repot lokalt kan ligga efter servern (sista commit 2026-08-19) | Verifiera att mallen i salt-masterns branch matchar |
| F4 | `api_base_url = https://cm.harica.gr` på sucm-test (hårdkodat i `settings.sls`, samma för test och prod) | Ingen separat Harica-testmiljö konfigurerad | **Bekräftat 2026-10-23: ett riktigt, publikt betrott cert utfärdades.** Order 10020, `CN=acmetest-haak0644.it.su.se, O=Stockholms universitet`, utfärdare `CN=GEANT TLS ECC 1, O=Hellenic Academic and Research Institutions CA, C=GR`, giltigt t.o.m. 2027-05-10, serie `0x0eecde42b50b39885829a5762fbf1910`. Kommer att finnas i CT-loggar. Revokera efter test (L3-02 kan användas) och inför separat test-CA för kommande körningar |
| F5 | Testverktyget sparade inte kontonyckeln (egen bugg) | Slumpnyckel per körning | Åtgärdat, nyckeln sparas i state-katalogen |
| F6 | **Bugg i SUCM:** ACME-utfärdat cert får ingen `Certificate`-rad, bara `ActiveCertificate` (orphan). `finalize` svarar ändå 200 och certet levereras. Följd: `revoke-cert` ger `unauthorized: No certificate issued to your account matches…` för kontots eget cert (L3-02 FAIL), och förnyelse kan inte hitta befintlig rad. | `[ACME] notify_group_id =` (tom, enligt `conf/sucm_conf.ini_example` "may be left empty") läses som `''` och skrivs till heltalskolumnen `Notify_Group_Id` → MySQL 1366 *Incorrect integer value ''*. `add_update_record()` sväljer felet och returnerar `"Failure"`, och `finalize_order()` kontrollerar inte resultatet. Syslog 10:53:49. | (a)+(b) Koden åtgärdad i sucm-repots arbetskatalog (ej committad/deployad): tom `notify_group_id` → `None` i `_load_acme_config()`; `submit_manual_csr()` avbryter innan CA-beställning om `Certificate`-raden inte kan sparas. (c) Alternativt sätt ett riktigt `notify_group_id` i testconfigen |
| F7 | **Bugg i SUCM:** signatur med `alg: RS256` mot ett EC-konto ger HTTP 500 med HTML i stället för problem+json (L3-08) | Troligen ett ohanterat undantag i `verify_signature()` när algoritmen inte matchar nyckeltypen (RS256-verifiering anropas på en EC-nyckel). Endast DoS/robusthet, ingen autentiseringsbypass: signaturen verifieras inte | Fånga alla undantag i JWS-verifieringen och svara `malformed`/`badSignatureAlgorithm`; kontrollera att `alg` passar JWK:ns `kty`/`crv` |
| F8 | `Link: <…/directory>;rel="index"` saknas på svar (L4-03) | Inte implementerat | Låg prioritet. Lägg till i `after_request` för `/acme/*` utom directory |

**Resultatkoder:** PASS / FAIL / SKIP / N/A (medvetet ej stött) / BLOCKED.
**Nivåer:** 1 = måste fungera för att få ut ett cert. 2 = förnyelse och grundläggande negativa fall. 3 = säkerhet/isolering. 4 = övrig RFC-konformitet.

## Förutsättningar (görs före körning)
| # | Åtgärd | Utförd |
|---|--------|--------|
| P1 | Konto skapat i portalen, EAB-uppgifter i `~/.config/sucm-acme-tester/tester.env` på testmaskinen | ☑ |
| P2 | Admin har aktiverat kontot | ☑ |
| P3 | Testdomänen ligger på kontots allow-list | ☑ |
| P4 | `[ACME]` i `sucm_conf.ini` satt (ca_plugin_name, secret_path, notify_group_id), **via salt** så att det överlever deploy | ☐ **saknas, se F1/F2** |
| P4b | Klarlagt vilken Harica-miljö som används och att ett testcert är ok (F4) | ☐ |
| P5 | Testmaskinen når sucm-test (directory svarar) | ☑ |

## Körning
```bash
cd ~/sucm-acme-tester                       # uppgifter läses från ~/.config/sucm-acme-tester/tester.env
PYTHONPATH=. python3 -m pytest -m level1 --junitxml=results-level1.xml   # nivå 1
PYTHONPATH=. python3 -m pytest -m "level1 and not issuance"              # utan certutfärdande
e2e/certbot.sh                                                          # certbot-smoke (kräver eget konto)
```

## Nivå 1 – Happy path (implementerad)
| ID | Testfall | RFC | Förväntat | Automatiserat | Resultat | Anm. |
|----|----------|-----|-----------|---------------|----------|------|
| L1-01 | Directory har newNonce/newAccount/newOrder | 7.1.1 | JSON med URL:er | `test_directory_has_required_resources` | **PASS** | |
| L1-02 | newNonce HEAD ger Replay-Nonce | 7.2 | 200/204 + header | `test_new_nonce_returns_replay_nonce` | **PASS** | |
| L1-03 | Nonces är unika | 6.5 | två olika värden | `test_nonces_are_unique` | **PASS** | |
| L1-04 | newAccount med korrekt EAB | 7.3.4 | 200/201 + Location | `TestFlow::test_1` | **PASS** | Kontot aktivt, EAB bunden till sparad nyckel |
| L1-05 | newOrder för tillåten domän | 7.4 | 201, status pending/ready | `TestFlow::test_2` | **PASS** | Order 10019 |
| L1-06 | Authorization(er) är valid | 7.5 | status valid (trust-baserat, by design) | `TestFlow::test_3` | **PASS** | |
| L1-07 | Finalize med matchande CSR | 7.4 | order blir valid + certificate-URL | `TestFlow::test_4` | **PASS** | Efter temporär `[ACME]`-config (F1). Kördes 2026-10-23, 8/8 på 12 s |
| L1-08 | Hämta certifikat | 7.4.2 | `application/pem-certificate-chain`, SAN innehåller domänen | `TestFlow::test_5` | **PASS** | Content-Type och SAN verifierade. Utfärdare: GEANT TLS ECC 1 (se F4) |
| L1-09 | certbot certonly end-to-end | – | cert i `live/`, `openssl x509` läser det | `e2e/certbot.sh` | ☐ | Kräver eget konto (annan nyckel än testaren) |

## Nivå 2 – Förnyelse och grundläggande negativa fall (delvis implementerad)
| ID | Testfall | RFC | Förväntat | Resultat | Anm. |
|----|----------|-----|-----------|----------|------|
| L2-01 | Ny order för samma domän (förnyelse) | 7.4 | nytt cert utfärdas, ersätter tidigare ActiveCertificate | ☐ | |
| L2-02 | Domän utanför allow-list | 7.4 | `rejectedIdentifier` | **PASS** | `test_l2_02` |
| L2-03 | Wildcard (`*.domän`) | 7.4 | `rejectedIdentifier` (avsiktligt, ej bugg) | **PASS** | `test_l2_03` |
| L2-04 | Okänt EAB-kid | 7.3.4 | `unauthorized`/`malformed` | **PASS** | `test_l2_04` |
| L2-05 | EAB med fel HMAC | 7.3.4 | avvisas | **PASS** | `test_l2_05` (slumpnyckel; avvisningen kan delvis bero på nyckelbindning, ej isolerat) |
| L2-06 | Återanvänd nonce | 6.5 | `badNonce` | **PASS** | `test_l2_06` |
| L2-07 | Ogiltig/gammal nonce | 6.5 | `badNonce` | **PASS** | `test_l2_07` |
| L2-08 | Finalize med CSR vars SAN inte matchar ordern | 7.4 | `badCSR` | **PASS** | `test_l2_08` (ingen utfärdning) |
| L2-09 | Finalize på order som inte är ready | 7.4 | `orderNotReady` | ☐ | Svårt att nå, ordrar blir `ready` direkt |
| L2-10 | Tom identifier-lista / okänd identifier-typ | 7.4 | `malformed`/`unsupportedIdentifier` | **PASS** | `test_l2_10`, `test_l2_10b` |
| L2-11 | Konto som inte är aktiverat | – | `unauthorized` | **PASS** (manuellt observerat) | 10:30, `requested but not yet activated` |

## Nivå 3 – Säkerhet och isolering (delvis implementerad)
| ID | Testfall | RFC | Förväntat | Resultat | Anm. |
|----|----------|-----|-----------|----------|------|
| L3-01 | Konto B hämtar konto A:s order/authz/cert | 10.x | nekas/404 | ☐ | |
| L3-02 | Revoke av eget cert | 7.6 | 200 | **FAIL** | 10:58, `unauthorized: No certificate issued to your account matches…` pga F6 (Certificate-rad saknas). Cert 180 (order 10020) är fortfarande ej revokerat |
| L3-03 | Revoke av annat kontos cert | 7.6 | `unauthorized` | ☐ | |
| L3-04 | Revoke med fel issuer/serial | 7.6 | nekas | ☐ | |
| L3-05 | Fel signatur | 6.2 | `malformed`/`unauthorized` | **PASS** | `test_l3_05` |
| L3-06 | `url` i header ≠ request-URL | 6.4 | avvisas | **PASS** | `test_l3_06` |
| L3-07 | Både `jwk` och `kid` | 6.2 | `malformed` | **PASS** | `test_l3_07` |
| L3-08 | Ej stödd alg (`none`, HS256 på yttre JWS, RS256 med EC-nyckel) | 6.2 | `badSignatureAlgorithm`/`malformed`, inget 500 | **FAIL** | `none`, `HS256`, saknad alg: PASS. **`RS256` med EC-nyckel ger HTTP 500 (HTML), se F7** |
| L3-09 | Trasig JSON, tom body, felaktig Content-Type | 6.2 | problem+json, inget 500 | **PASS** | `test_l3_09`, `test_l3_09b` (5 varianter + fel Content-Type, alla 4xx) |
| L3-10 | Överstor body (5 MB) | – | avvisas | **PASS** | `test_l3_10` |
| L3-11 | SQL-liknande/hostile identifier (SQLi, 5000 tecken, CRLF) | – | avvisas, inget 500 | **PASS** | `test_l3_11` (4 varianter) |
| L3-12 | newAccount med redan bunden EAB-kid och annan nyckel | 7.3.4 | avvisas | **PASS** | Manuellt 10:33 och automatiserat `test_l3_12` |

## Nivå 4 – Övrig konformitet (delvis implementerad)
| ID | Testfall | RFC | Förväntat | Resultat | Anm. |
|----|----------|-----|-----------|----------|------|
| L4-01 | Felsvar är `application/problem+json` med `urn:ietf:params:acme:error:*` | 6.7 | ja | **PASS** | `test_l4_01` |
| L4-02 | Replay-Nonce i alla svar, även fel | 6.5 | ja | **PASS** | `test_l4_02` |
| L4-03 | `Link: <directory>;rel="index"` | 7.1 | ja | **FAIL** | Header saknas på svar från newOrder (F8) |
| L4-04 | `Cache-Control: no-store` på newNonce | 7.2 | ja | **PASS** | `test_l4_04` |
| L4-05 | `onlyReturnExisting` | 7.3.1 | stöd eller N/A | ☐ | |
| L4-06 | Account update / deactivate | 7.3.2, 7.3.6 | stöd eller N/A | ☐ | |
| L4-07 | Key rollover | 7.3.5 | stöd eller N/A | ☐ | |
| L4-08 | Orderlista för konto | 7.1.2.1 | stöd eller N/A | ☐ | |
| L4-09 | ARI (RFC 9773) | 9773 | stöd eller N/A | ☐ | |

## Sammanfattning (uppdateras efter varje körning)
| Nivå | PASS | FAIL | BLOCKED | Ej körda | Godkänd? |
|------|------|------|---------|----------|----------|
| 1 | 8 (L1-01–08) | 0 | 0 | 1 (L1-09 certbot) | ☐ (väntar på certbot) |
| 2 | 9 (L2-02–08, 10, 11) | 0 | 0 | 2 (L2-01 förnyelse, L2-09) | ☐ |
| 3 | 8 (L3-05–07, 09–12) | 2 (L3-02 revoke, L3-08 RS256) | 0 | 4 (L3-01, 03, 04 + cross-account) | ☐ |
| 4 | 3 (L4-01, 02, 04) | 1 (L4-03) | 0 | 5 (L4-05–09) | ☐ |

**Status 2026-10-23:** hela flödet med egen klient fungerar (directory → newAccount med EAB → newOrder → authz →
finalize → cert), efter att `[ACME]` lagts till temporärt (F1). Återstår: certbot-smoke (L1-09), permanent `[ACME]`
i salt-mallen (F2) och att Harica-miljön är produktion (F4: riktigt cert utfärdat, bör revokeras).

**Rekommendation (go / no-go för SUCM v0.12.0 ACME):** `________` (avgörs när nivå 1 är grön)

## Efter test
- ☐ Konto 10015 deaktiverat, EAB-nycklarna ogiltiga
- ☐ `tester.env` raderad från testmaskinen
- ☐ Testcert/ActiveCertificate och Vault-poster städade
- ☐ Temporär `[ACME]`-sektion borttagen från `/local/cert-app/conf/sucm_conf.ini` på cert-test-app02 (eller ersatt av salt-mallen), samt `sucm_conf.ini.bak-acmetest` raderad
