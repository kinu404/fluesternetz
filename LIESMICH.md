# FlüsterNetz — Sicheres Peer-to-Peer Chatprotokoll

## Übersicht

FlüsterNetz ist ein sicheres Peer-to-Peer (P2P) Chatprotokoll und die zugehörige Applikation, die verschlüsselte Kommunikation zwischen zwei Rechnern über ein Netzwerk ermöglicht. Das Protokoll setzt auf TCP (Schicht 4) und TLS 1.2+ (Transportschichtsicherheit) auf und gewährleistet Vertraulichkeit, Integrität und Verfügbarkeit der Kommunikation.

## Systemvoraussetzungen

- **Betriebssystem:** Kali Linux 2025.4 x86_64 (VirtualBox-Abbild)
  - SHA256: `6e3a70e3be441f6eab8c034493338dc032e4f5a87f93692d5fc486f1e8022ac4`
- **Python:** Version 3.x (im Abbild vorinstalliert)
- **Python-Bibliotheken** (alle im Kali-Abbild enthalten):
  - `socket`, `ssl`, `threading`, `struct`, `hashlib`, `hmac` (Standardbibliothek)
  - `cryptography` (für TLS-Zertifikatserstellung)
- **Netzwerk:** Zwei Rechner, die über ein TCP/IP-Netzwerk verbunden sind

## Installation

Es ist keine zusätzliche Installation von Paketen notwendig. Alle benötigten Bibliotheken sind in Kali Linux 2025.4 enthalten.

1. Kopieren Sie die Datei `fluesternetz.py` auf beide Rechner:
   ```bash
   # Zum Beispiel per SCP von Rechner A nach Rechner B:
   scp fluesternetz.py benutzer@<IP_RECHNER_B>:/home/benutzer/
   ```

2. Stellen Sie sicher, dass die Datei ausführbar ist:
   ```bash
   chmod +x fluesternetz.py
   ```

## Netzwerk-Einrichtung (VirtualBox)

Für die Kommunikation zwischen zwei virtuellen Maschinen in VirtualBox:

1. **Internes Netzwerk einrichten:**
   - Öffnen Sie die Einstellungen beider VMs → Netzwerk → Adapter 1
   - Wählen Sie „Internes Netzwerk" und vergeben Sie den gleichen Netzwerknamen (z. B. `fluesternetz`)

2. **IP-Adressen zuweisen:**
   ```bash
   # Auf Rechner A:
   sudo ip addr add 10.0.0.1/24 dev eth0
   sudo ip link set eth0 up

   # Auf Rechner B:
   sudo ip addr add 10.0.0.2/24 dev eth0
   sudo ip link set eth0 up
   ```

3. **Verbindung testen:**
   ```bash
   # Von Rechner A:
   ping 10.0.0.2
   ```

## Nutzung

### Schritt 1: Server starten (Rechner A)

Auf dem ersten Rechner wird der Chat im Server-Modus gestartet. Der Server wartet auf eine eingehende Verbindung.

```bash
python3 fluesternetz.py server -n Alice
```

Optionale Parameter:
- `-n` / `--name`: Benutzername (Standard: „Anonym")
- `-p` / `--port`: Port-Nummer (Standard: 9777)

### Schritt 2: Client verbinden (Rechner B)

Auf dem zweiten Rechner wird der Chat im Client-Modus gestartet und eine Verbindung zum Server hergestellt.

```bash
python3 fluesternetz.py client -z 10.0.0.1 -n Bob
```

Pflichtparameter:
- `-z` / `--ziel`: IP-Adresse des Servers

Optionale Parameter:
- `-n` / `--name`: Benutzername (Standard: „Anonym")
- `-p` / `--port`: Port-Nummer (Standard: 9777)

### Schritt 3: Chatten

Nach dem erfolgreichen Verbindungsaufbau und Handshake können beide Seiten Nachrichten eingeben. Eingaben werden mit der Eingabetaste gesendet.

```
Du (Alice): Hallo, Welt!
[14:30:15] Bob: Hallo, Welt! Wie ist das Wetter?
Du (Alice): Das Wetter ist sehr schön.
```

### Befehle im Chat

| Befehl   | Beschreibung                          |
|----------|---------------------------------------|
| `/quit`  | Chat beenden und Verbindung trennen   |
| `/info`  | Verbindungsinformationen anzeigen     |

## Netzwerkverkehr aufzeichnen

Um den Netzwerkverkehr mit Wireshark oder tcpdump aufzuzeichnen:

```bash
# Mit tcpdump auf dem Netzwerkinterface aufzeichnen:
sudo tcpdump -i eth0 -w Aufzeichnung.pcap port 9777
```

Alternativ kann Wireshark mit grafischer Oberfläche verwendet werden:
1. Wireshark starten: `sudo wireshark`
2. Netzwerkinterface auswählen (z. B. `eth0`)
3. Aufzeichnung starten → Chat durchführen → Aufzeichnung stoppen
4. Datei speichern als `Aufzeichnung.pcap`

## Fehlerbehebung

- **„Verbindung abgelehnt"**: Prüfen Sie, ob der Server läuft und die Firewall Port 9777 nicht blockiert (`sudo ufw allow 9777/tcp`).
- **„Netzwerk nicht erreichbar"**: Prüfen Sie die IP-Konfiguration und Netzwerk-Einstellungen der VMs.
- **TLS-Fehler**: Stellen Sie sicher, dass die `cryptography`-Bibliothek installiert ist (`python3 -c "import cryptography"`).

## Autoren

[Namen hier eintragen]
