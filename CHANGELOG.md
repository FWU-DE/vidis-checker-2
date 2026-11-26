# Changelog

Eine Version gilt für alles, was externe Testsuiten und Agents lesen: API (`/discovery`, `/checks`, `/criteria`, `/openapi.json`), Job- und Ergebnis-JSON, Callback und Belegfelder in den Captures. Sie steht in `/discovery` unter `api_version`, im Header `X-VIDIS-API-Version` und in jedem Ergebnis.

- **MAJOR**: Feld, Endpunkt, Prüfung oder Kriterium entfällt oder wird umbenannt, oder ein Wert ändert seine Bedeutung.
- **MINOR**: Neue Felder, Endpunkte, Prüfungen oder Kriterien.
- **PATCH**: Eine Prüfung entscheidet genauer, ohne dass sich das Format ändert.

Die VIDIS-Prüfkriterien (V0.2) haben eine eigene Version (`criteria_catalog.version`).

## 1.0.0 – 2026-11-26

- Erste versionierte Fassung des Vertrags; `api_version` in `/discovery`, Jobs, Ergebnissen, Captures und Callback, Header `X-VIDIS-API-Version`.
- Kriterien statt Prüfungen auswählen: `criteria` in `POST /jobs`, `POST /criteria/<code>`, `run` in `/discovery` mit `criteria`.
- RDS-CUC-377 entscheidet allein `site.tracking_mechanisms`; „kein Tracking wünschen“ gilt nicht mehr als Beleg.
- Einzelprüfungen geben Kriterien, die eine andere Prüfung bewertet, nicht mehr als MANUELL aus (RDS-CUC-453 bei `documents.analysis`).
- Coverage-Matrix nennt `target_url` als Eingabe für Dokument-Kriterien.
