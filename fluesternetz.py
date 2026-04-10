#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FlüsterNetz - Sicheres Peer-to-Peer Chatprotokoll
===================================================
Dieses Programm implementiert das FlüsterNetz-Chatprotokoll,
ein sicheres P2P-Kommunikationsprotokoll für verschlüsselte Nachrichten.

Autoren: [Namen hier eintragen]
Version: 1.0
"""

import socket       # Netzwerkverbindungen über TCP-Sockets
import ssl          # TLS/SSL-Verschlüsselung der Transportschicht
import threading    # Nebenläufige Verarbeitung für Senden/Empfangen
import struct       # Binäres Packen/Entpacken von Protokollfeldern
import hashlib      # SHA-256 Prüfsummenberechnung für Integrität
import hmac         # HMAC-basierte Nachrichtenauthentifizierung
import os           # Betriebssystemfunktionen (Zufallszahlen)
import sys          # Systemfunktionen (Kommandozeilenargumente)
import time         # Zeitstempel für Nachrichten
import json         # JSON-Serialisierung für Handshake-Daten
import argparse     # Kommandozeilenargument-Verarbeitung
import secrets      # Kryptographisch sichere Zufallszahlen
import signal       # Signalbehandlung für sauberes Beenden

# ============================================================
# Protokollkonstanten
# ============================================================

PROTOKOLL_VERSION = 1          # Aktuelle Protokollversion
PROTOKOLL_PORT = 9777          # Standardport für FlüsterNetz
MAGISCHE_BYTES = b'\xF1\xCE'  # Magische Bytes zur Paketerkennung ("FlüsterNetz Cipher Envelope")
MAX_NUTZLAST = 65535           # Maximale Nutzlastgröße in Bytes

# Nachrichtentypen als ganzzahlige Konstanten
class NachrichtenTyp:
    """Definiert die verschiedenen Nachrichtentypen im FlüsterNetz-Protokoll."""
    HALLO = 0x01           # Verbindungsaufbau: Hallo-Nachricht
    HALLO_ANTWORT = 0x02   # Verbindungsaufbau: Antwort auf Hallo
    SCHLUESSEL = 0x03      # Schlüsselaustausch-Nachricht
    CHAT = 0x10            # Chat-Textnachricht
    BESTAETIGUNG = 0x11    # Empfangsbestätigung (ACK)
    HERZSCHLAG = 0x20      # Herzschlag / Keep-Alive
    TSCHUESS = 0xF0        # Verbindungsabbau: Abschiedsnachricht
    FEHLER = 0xFF          # Fehlernachricht

    # Zuordnung von Typ-Nummern zu lesbaren Namen
    NAMEN = {
        0x01: "HALLO",
        0x02: "HALLO_ANTWORT",
        0x03: "SCHLUESSEL",
        0x10: "CHAT",
        0x11: "BESTAETIGUNG",
        0x20: "HERZSCHLAG",
        0xF0: "TSCHUESS",
        0xFF: "FEHLER",
    }

    @staticmethod
    def name_von(typ):
        """Gibt den lesbaren Namen eines Nachrichtentyps zurück."""
        return NachrichtenTyp.NAMEN.get(typ, f"UNBEKANNT(0x{typ:02X})")


# ============================================================
# Protokollpaket-Klasse
# ============================================================

class FluesternetzPaket:
    """
    Repräsentiert ein FlüsterNetz-Protokollpaket.

    Paketformat (Header: 16 Bytes fest):
    +--------+--------+---------+-------+--------+----------+-----------+---------+
    | Feld   | Magic  | Version | Typ   | Flags  | Sequenz  | Zeitstempel| Länge  |
    | Bytes  |   2    |    1    |   1   |   1    |    2     |     4      |    2   |
    | Offset |   0    |    2    |   3   |   4    |    5     |     7      |   11   |
    +--------+--------+---------+-------+--------+----------+-----------+---------+
    | Feld   | Prüfsumme (HMAC-SHA256, 32 Bytes)                                  |
    | Bytes  |   32                                                               |
    | Offset |   13                                                               |
    +--------+--------+---------+-------+--------+----------+-----------+---------+
    | Feld   | Nutzlast (variable Länge)                                          |
    | Bytes  |   0 - 65535                                                        |
    | Offset |   45                                                               |
    +--------+--------+---------+-------+--------+----------+-----------+---------+

    Gesamter Header: 13 Bytes + 32 Bytes HMAC = 45 Bytes
    """

    # Format des Headers: ! = Network Byte Order (Big-Endian)
    # 2s = Magic (2 Bytes), B = Version (1 Byte), B = Typ (1 Byte),
    # B = Flags (1 Byte), H = Sequenznummer (2 Bytes),
    # I = Zeitstempel (4 Bytes), H = Nutzlastlänge (2 Bytes)
    HEADER_FORMAT = '!2sBBBHIH'
    HEADER_LAENGE = struct.calcsize(HEADER_FORMAT)  # 13 Bytes
    HMAC_LAENGE = 32  # SHA-256 HMAC-Länge in Bytes
    GESAMT_HEADER = HEADER_LAENGE + HMAC_LAENGE     # 45 Bytes

    def __init__(self, typ, nutzlast=b'', sequenz=0, flags=0):
        """
        Erstellt ein neues FlüsterNetz-Paket.

        Parameter:
            typ: Nachrichtentyp (siehe NachrichtenTyp-Klasse)
            nutzlast: Die zu sendenden Daten als Bytes
            sequenz: Sequenznummer zur Nachrichtenverfolgung
            flags: Zusätzliche Flags (Bit 0: Verschlüsselt, Bit 1: Komprimiert)
        """
        self.magic = MAGISCHE_BYTES          # Magische Bytes zur Paketerkennung
        self.version = PROTOKOLL_VERSION     # Protokollversion
        self.typ = typ                       # Nachrichtentyp
        self.flags = flags                   # Flags-Feld
        self.sequenz = sequenz               # Sequenznummer
        self.zeitstempel = int(time.time())  # Aktueller Unix-Zeitstempel
        self.nutzlast = nutzlast             # Nutzdaten
        self.hmac_wert = b'\x00' * self.HMAC_LAENGE  # Platzhalter für HMAC

    def packen(self, hmac_schluessel=None):
        """
        Serialisiert das Paket in ein Byte-Array zur Übertragung.

        Parameter:
            hmac_schluessel: Geheimer Schlüssel für HMAC-Berechnung (optional)

        Rückgabe:
            Byte-Array mit dem vollständigen Paket
        """
        # Nutzlastlänge berechnen und begrenzen
        nutzlast_laenge = len(self.nutzlast)
        if nutzlast_laenge > MAX_NUTZLAST:
            raise ValueError(f"Nutzlast zu groß: {nutzlast_laenge} > {MAX_NUTZLAST}")

        # Header zusammenbauen
        header = struct.pack(
            self.HEADER_FORMAT,
            self.magic,
            self.version,
            self.typ,
            self.flags,
            self.sequenz,
            self.zeitstempel,
            nutzlast_laenge
        )

        # HMAC berechnen, wenn Schlüssel vorhanden
        if hmac_schluessel:
            # HMAC über Header + Nutzlast berechnen
            zu_signieren = header + self.nutzlast
            self.hmac_wert = hmac.new(
                hmac_schluessel, zu_signieren, hashlib.sha256
            ).digest()
        else:
            self.hmac_wert = b'\x00' * self.HMAC_LAENGE

        # Gesamtpaket: Header + HMAC + Nutzlast
        return header + self.hmac_wert + self.nutzlast

    @classmethod
    def entpacken(cls, daten, hmac_schluessel=None):
        """
        Deserialisiert ein Byte-Array in ein FlüsterNetz-Paket.

        Parameter:
            daten: Empfangene Rohdaten als Bytes
            hmac_schluessel: Geheimer Schlüssel zur HMAC-Überprüfung (optional)

        Rückgabe:
            Ein FluesternetzPaket-Objekt oder None bei Fehler
        """
        # Mindestlänge prüfen
        if len(daten) < cls.GESAMT_HEADER:
            print(f"[FEHLER] Paket zu kurz: {len(daten)} < {cls.GESAMT_HEADER} Bytes")
            return None

        # Header entpacken
        header_daten = daten[:cls.HEADER_LAENGE]
        magic, version, typ, flags, sequenz, zeitstempel, nutzlast_laenge = struct.unpack(
            cls.HEADER_FORMAT, header_daten
        )

        # Magische Bytes prüfen
        if magic != MAGISCHE_BYTES:
            print(f"[FEHLER] Ungültige magische Bytes: {magic.hex()}")
            return None

        # Version prüfen
        if version != PROTOKOLL_VERSION:
            print(f"[WARNUNG] Unbekannte Protokollversion: {version}")

        # HMAC extrahieren
        hmac_empfangen = daten[cls.HEADER_LAENGE:cls.GESAMT_HEADER]

        # Nutzlast extrahieren
        nutzlast = daten[cls.GESAMT_HEADER:cls.GESAMT_HEADER + nutzlast_laenge]

        # HMAC verifizieren, wenn Schlüssel vorhanden
        if hmac_schluessel:
            zu_verifizieren = header_daten + nutzlast
            hmac_erwartet = hmac.new(
                hmac_schluessel, zu_verifizieren, hashlib.sha256
            ).digest()
            if not hmac.compare_digest(hmac_empfangen, hmac_erwartet):
                print("[FEHLER] HMAC-Überprüfung fehlgeschlagen! Nachricht manipuliert?")
                return None

        # Paket-Objekt erstellen
        paket = cls(typ=typ, nutzlast=nutzlast, sequenz=sequenz, flags=flags)
        paket.magic = magic
        paket.version = version
        paket.zeitstempel = zeitstempel
        paket.hmac_wert = hmac_empfangen
        return paket

    def __str__(self):
        """Gibt eine lesbare Darstellung des Pakets zurück."""
        typ_name = NachrichtenTyp.name_von(self.typ)
        return (
            f"[FlüsterNetz v{self.version}] Typ={typ_name} "
            f"Seq={self.sequenz} Flags=0x{self.flags:02X} "
            f"Nutzlast={len(self.nutzlast)} Bytes"
        )


# ============================================================
# FlüsterNetz Chat-Klasse
# ============================================================

class FluesternetzChat:
    """
    Hauptklasse für den FlüsterNetz P2P-Chat.
    Verwaltet Verbindungsaufbau, Nachrichtenaustausch und -abbau.
    """

    def __init__(self, benutzername="Anonym"):
        """
        Initialisiert eine neue Chat-Instanz.

        Parameter:
            benutzername: Der Anzeigename des Benutzers
        """
        self.benutzername = benutzername     # Anzeigename im Chat
        self.verbunden = False               # Verbindungsstatus
        self.socket = None                   # Netzwerk-Socket
        self.tls_socket = None               # TLS-verschlüsselter Socket
        self.sequenz_zaehler = 0             # Laufende Sequenznummer
        self.hmac_schluessel = None          # Gemeinsamer HMAC-Schlüssel
        self.empfangs_thread = None          # Thread zum Nachrichtenempfang
        self.partner_name = ""               # Name des Chat-Partners
        self.beenden_ereignis = threading.Event()  # Signal zum Beenden

    def _naechste_sequenz(self):
        """Gibt die nächste Sequenznummer zurück und erhöht den Zähler."""
        self.sequenz_zaehler += 1
        return self.sequenz_zaehler % 65536  # Auf 16-Bit begrenzen

    def _tls_kontext_erstellen(self, ist_server=False):
        """
        Erstellt einen TLS-Kontext für sichere Kommunikation.

        Parameter:
            ist_server: True für Serverseite, False für Clientseite

        Rückgabe:
            Ein konfiguriertes ssl.SSLContext-Objekt
        """
        if ist_server:
            # Server-seitiger TLS-Kontext
            kontext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        else:
            # Client-seitiger TLS-Kontext
            kontext = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            # Für P2P: Zertifikatsprüfung deaktivieren (selbstsignierte Zertifikate)
            kontext.check_hostname = False
            kontext.verify_mode = ssl.CERT_NONE

        # Sichere Protokollversionen erzwingen
        kontext.minimum_version = ssl.TLSVersion.TLSv1_2
        return kontext

    def _zertifikate_erstellen(self):
        """
        Erstellt selbstsignierte TLS-Zertifikate für den Server.
        Speichert Zertifikat und Schlüssel als temporäre Dateien.

        Rückgabe:
            Tuple (zertifikat_pfad, schluessel_pfad)
        """
        from cryptography import x509                              # X.509-Zertifikatserstellung
        from cryptography.x509.oid import NameOID                  # OIDs für Zertifikatsfelder
        from cryptography.hazmat.primitives import hashes           # Hash-Algorithmen
        from cryptography.hazmat.primitives import serialization    # Schlüsselserialisierung
        from cryptography.hazmat.primitives.asymmetric import rsa   # RSA-Schlüsselgenerierung
        import datetime  # Zeitangaben für Gültigkeit

        # RSA-Schlüsselpaar generieren (2048 Bit)
        schluessel = rsa.generate_private_key(
            public_exponent=65537,   # Standard öffentlicher Exponent
            key_size=2048,           # Schlüssellänge in Bit
        )

        # Zertifikatsdaten definieren
        subjekt = aussteller = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"FlüsterNetz P2P Chat"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"FlüsterNetz"),
        ])

        # Selbstsigniertes Zertifikat erstellen
        zertifikat = (
            x509.CertificateBuilder()
            .subject_name(subjekt)
            .issuer_name(aussteller)
            .public_key(schluessel.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(schluessel, hashes.SHA256())
        )

        # Schlüssel und Zertifikat in temporäre Dateien schreiben
        schluessel_pfad = "/tmp/fluesternetz_schluessel.pem"
        zertifikat_pfad = "/tmp/fluesternetz_zertifikat.pem"

        # Privaten Schlüssel speichern
        with open(schluessel_pfad, "wb") as f:
            f.write(schluessel.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        # Zertifikat speichern
        with open(zertifikat_pfad, "wb") as f:
            f.write(zertifikat.public_bytes(serialization.Encoding.PEM))

        print("[INFO] Selbstsignierte TLS-Zertifikate erstellt.")
        return zertifikat_pfad, schluessel_pfad

    def _senden(self, paket):
        """
        Sendet ein FlüsterNetz-Paket über den TLS-Socket.

        Parameter:
            paket: Das zu sendende FluesternetzPaket-Objekt
        """
        try:
            # Paket serialisieren mit HMAC-Schlüssel
            daten = paket.packen(self.hmac_schluessel)
            # Länge als 4-Byte-Prefix senden (Framing)
            laengen_prefix = struct.pack('!I', len(daten))
            ziel_socket = self.tls_socket if self.tls_socket else self.socket
            ziel_socket.sendall(laengen_prefix + daten)
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"\n[FEHLER] Senden fehlgeschlagen: {e}")
            self.verbunden = False

    def _empfangen(self, sock):
        """
        Empfängt ein vollständiges FlüsterNetz-Paket vom Socket.

        Parameter:
            sock: Der Socket, von dem gelesen wird

        Rückgabe:
            Ein FluesternetzPaket-Objekt oder None bei Fehler
        """
        try:
            # Zuerst die Paketlänge lesen (4 Bytes)
            laengen_daten = self._alles_lesen(sock, 4)
            if not laengen_daten:
                return None
            paket_laenge = struct.unpack('!I', laengen_daten)[0]

            # Dann die eigentlichen Paketdaten lesen
            paket_daten = self._alles_lesen(sock, paket_laenge)
            if not paket_daten:
                return None

            # Paket deserialisieren und HMAC prüfen
            return FluesternetzPaket.entpacken(paket_daten, self.hmac_schluessel)

        except (ConnectionResetError, OSError) as e:
            return None

    def _alles_lesen(self, sock, anzahl):
        """
        Liest exakt die angegebene Anzahl an Bytes vom Socket.

        Parameter:
            sock: Der Socket, von dem gelesen wird
            anzahl: Die zu lesende Byteanzahl

        Rückgabe:
            Die gelesenen Bytes oder None bei Fehler
        """
        daten = b''
        while len(daten) < anzahl:
            try:
                stueck = sock.recv(anzahl - len(daten))
                if not stueck:
                    return None
                daten += stueck
            except (ConnectionResetError, OSError):
                return None
        return daten

    def _handshake_ausfuehren(self, ist_server, sock):
        """
        Führt den FlüsterNetz-Handshake durch.
        Tauscht Benutzernamen und vereinbart einen gemeinsamen HMAC-Schlüssel.

        Parameter:
            ist_server: True wenn dieser Knoten der Server ist
            sock: Der zu verwendende Socket
        """
        if ist_server:
            # === Server-Seite: Auf HALLO warten ===
            print("[INFO] Warte auf Handshake vom Client...")

            # HALLO-Paket empfangen
            paket = self._empfangen(sock)
            if not paket or paket.typ != NachrichtenTyp.HALLO:
                raise ConnectionError("Ungültiges HALLO-Paket empfangen")

            # Client-Daten auslesen
            client_daten = json.loads(paket.nutzlast.decode('utf-8'))
            self.partner_name = client_daten.get('benutzername', 'Unbekannt')
            print(f"[INFO] Verbindungsanfrage von: {self.partner_name}")

            # Gemeinsamen HMAC-Schlüssel generieren
            self.hmac_schluessel = secrets.token_bytes(32)

            # HALLO_ANTWORT senden mit Schlüssel und eigenem Namen
            antwort_daten = json.dumps({
                'benutzername': self.benutzername,
                'hmac_schluessel': self.hmac_schluessel.hex(),
                'status': 'akzeptiert'
            }).encode('utf-8')

            antwort = FluesternetzPaket(
                typ=NachrichtenTyp.HALLO_ANTWORT,
                nutzlast=antwort_daten,
                sequenz=self._naechste_sequenz()
            )
            self._tls_senden(sock, antwort)

        else:
            # === Client-Seite: HALLO senden ===
            hallo_daten = json.dumps({
                'benutzername': self.benutzername,
                'version': PROTOKOLL_VERSION,
            }).encode('utf-8')

            hallo = FluesternetzPaket(
                typ=NachrichtenTyp.HALLO,
                nutzlast=hallo_daten,
                sequenz=self._naechste_sequenz()
            )
            self._tls_senden(sock, hallo)

            # Auf HALLO_ANTWORT warten
            paket = self._empfangen(sock)
            if not paket or paket.typ != NachrichtenTyp.HALLO_ANTWORT:
                raise ConnectionError("Ungültige HALLO_ANTWORT empfangen")

            # Server-Daten auslesen
            server_daten = json.loads(paket.nutzlast.decode('utf-8'))
            self.partner_name = server_daten.get('benutzername', 'Unbekannt')
            self.hmac_schluessel = bytes.fromhex(server_daten['hmac_schluessel'])

            if server_daten.get('status') != 'akzeptiert':
                raise ConnectionError("Verbindung vom Server abgelehnt")

        print(f"[INFO] Handshake erfolgreich mit: {self.partner_name}")
        self.verbunden = True

    def _tls_senden(self, sock, paket):
        """
        Sendet ein Paket über den angegebenen Socket (für Handshake-Phase).

        Parameter:
            sock: Der Socket zum Senden
            paket: Das zu sendende Paket
        """
        daten = paket.packen(self.hmac_schluessel)
        laengen_prefix = struct.pack('!I', len(daten))
        sock.sendall(laengen_prefix + daten)

    def _empfangs_schleife(self):
        """
        Hauptschleife zum Empfangen von Nachrichten.
        Läuft in einem eigenen Thread.
        """
        ziel_socket = self.tls_socket if self.tls_socket else self.socket
        while self.verbunden and not self.beenden_ereignis.is_set():
            paket = self._empfangen(ziel_socket)
            if paket is None:
                if self.verbunden:
                    print(f"\n[INFO] Verbindung zu {self.partner_name} verloren.")
                    self.verbunden = False
                break

            # Paket je nach Typ verarbeiten
            self._paket_verarbeiten(paket)

    def _paket_verarbeiten(self, paket):
        """
        Verarbeitet ein empfangenes Paket je nach Nachrichtentyp.

        Parameter:
            paket: Das empfangene FluesternetzPaket-Objekt
        """
        if paket.typ == NachrichtenTyp.CHAT:
            # Chat-Nachricht anzeigen
            nachricht = paket.nutzlast.decode('utf-8')
            zeitstempel = time.strftime('%H:%M:%S', time.localtime(paket.zeitstempel))
            print(f"\n[{zeitstempel}] {self.partner_name}: {nachricht}")
            print(f"Du ({self.benutzername}): ", end='', flush=True)

            # Empfangsbestätigung senden
            bestaetigung = FluesternetzPaket(
                typ=NachrichtenTyp.BESTAETIGUNG,
                nutzlast=struct.pack('!H', paket.sequenz),
                sequenz=self._naechste_sequenz()
            )
            self._senden(bestaetigung)

        elif paket.typ == NachrichtenTyp.BESTAETIGUNG:
            # Empfangsbestätigung verarbeiten (still)
            pass

        elif paket.typ == NachrichtenTyp.HERZSCHLAG:
            # Herzschlag-Antwort senden
            antwort = FluesternetzPaket(
                typ=NachrichtenTyp.HERZSCHLAG,
                sequenz=self._naechste_sequenz()
            )
            self._senden(antwort)

        elif paket.typ == NachrichtenTyp.TSCHUESS:
            # Verbindungsabbau vom Partner
            print(f"\n[INFO] {self.partner_name} hat den Chat verlassen.")
            self.verbunden = False

        elif paket.typ == NachrichtenTyp.FEHLER:
            # Fehlermeldung anzeigen
            fehlermeldung = paket.nutzlast.decode('utf-8')
            print(f"\n[FEHLER vom Partner] {fehlermeldung}")

        else:
            print(f"\n[WARNUNG] Unbekannter Nachrichtentyp: {NachrichtenTyp.name_von(paket.typ)}")

    def nachricht_senden(self, text):
        """
        Sendet eine Chat-Nachricht an den Partner.

        Parameter:
            text: Der zu sendende Nachrichtentext
        """
        if not self.verbunden:
            print("[FEHLER] Keine Verbindung vorhanden.")
            return

        # Chat-Paket erstellen
        paket = FluesternetzPaket(
            typ=NachrichtenTyp.CHAT,
            nutzlast=text.encode('utf-8'),
            sequenz=self._naechste_sequenz(),
            flags=0x01  # Flag: Nachricht wird über TLS-verschlüsselten Kanal gesendet
        )
        self._senden(paket)

    def als_server_starten(self, port=PROTOKOLL_PORT):
        """
        Startet den Chat im Server-Modus (wartet auf eingehende Verbindung).

        Parameter:
            port: Der Port, auf dem gehört werden soll
        """
        print(f"╔══════════════════════════════════════════╗")
        print(f"║     FlüsterNetz Chat - Server-Modus      ║")
        print(f"╠══════════════════════════════════════════╣")
        print(f"║  Benutzername: {self.benutzername:<25s}  ║")
        print(f"║  Port: {port:<32d}                       ║")
        print(f"╚══════════════════════════════════════════╝")
        print()

        # TLS-Zertifikate erstellen
        zertifikat_pfad, schluessel_pfad = self._zertifikate_erstellen()

        # Server-Socket erstellen und konfigurieren
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(1)  # Maximal eine eingehende Verbindung (P2P)

        print(f"[INFO] Warte auf Verbindung auf Port {port}...")

        try:
            # Auf Client-Verbindung warten
            client_socket, adresse = server_socket.accept()
            print(f"[INFO] Verbindung von {adresse[0]}:{adresse[1]}")

            # TLS-Kontext konfigurieren und Socket umwickeln
            tls_kontext = self._tls_kontext_erstellen(ist_server=True)
            tls_kontext.load_cert_chain(zertifikat_pfad, schluessel_pfad)
            self.tls_socket = tls_kontext.wrap_socket(client_socket, server_side=True)
            self.socket = client_socket

            print(f"[INFO] TLS-Verbindung hergestellt: {self.tls_socket.version()}")

            # Handshake durchführen
            self._handshake_ausfuehren(ist_server=True, sock=self.tls_socket)

            # Chat-Schleife starten
            self._chat_schleife()

        except KeyboardInterrupt:
            print("\n[INFO] Server wird beendet...")
        except Exception as e:
            print(f"[FEHLER] {e}")
        finally:
            self._aufraeumen()
            server_socket.close()
            # Zertifikate aufräumen
            for pfad in [zertifikat_pfad, schluessel_pfad]:
                if os.path.exists(pfad):
                    os.remove(pfad)

    def als_client_verbinden(self, ziel_adresse, port=PROTOKOLL_PORT):
        """
        Verbindet sich als Client mit einem FlüsterNetz-Server.

        Parameter:
            ziel_adresse: IP-Adresse oder Hostname des Servers
            port: Port des Servers
        """
        print(f"╔══════════════════════════════════════════╗")
        print(f"║     FlüsterNetz Chat - Client-Modus      ║")
        print(f"╠══════════════════════════════════════════╣")
        print(f"║  Benutzername: {self.benutzername:<25s}  ║")
        print(f"║  Ziel: {ziel_adresse:<20s}:{port:<10d}   ║")
        print(f"╚══════════════════════════════════════════╝")
        print()

        try:
            # TCP-Verbindung herstellen
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((ziel_adresse, port))
            print(f"[INFO] TCP-Verbindung zu {ziel_adresse}:{port} hergestellt.")

            # TLS-Kontext konfigurieren und Socket umwickeln
            tls_kontext = self._tls_kontext_erstellen(ist_server=False)
            self.tls_socket = tls_kontext.wrap_socket(
                self.socket, server_hostname=ziel_adresse
            )
            print(f"[INFO] TLS-Verbindung hergestellt: {self.tls_socket.version()}")

            # Handshake durchführen
            self._handshake_ausfuehren(ist_server=False, sock=self.tls_socket)

            # Chat-Schleife starten
            self._chat_schleife()

        except ConnectionRefusedError:
            print(f"[FEHLER] Verbindung zu {ziel_adresse}:{port} abgelehnt.")
        except KeyboardInterrupt:
            print("\n[INFO] Verbindung wird beendet...")
        except Exception as e:
            print(f"[FEHLER] {e}")
        finally:
            self._aufraeumen()

    def _chat_schleife(self):
        """
        Hauptschleife für den Chat-Betrieb.
        Startet den Empfangs-Thread und verarbeitet Benutzereingaben.
        """
        print()
        print(f"════════════════════════════════════════════")
        print(f"  Chat mit {self.partner_name} gestartet!")
        print(f"  Zum Beenden '/quit' eingeben.")
        print(f"════════════════════════════════════════════")
        print()

        # Empfangs-Thread starten
        self.empfangs_thread = threading.Thread(
            target=self._empfangs_schleife,
            daemon=True,   # Thread wird beim Programmende automatisch beendet
            name="Empfangs-Thread"
        )
        self.empfangs_thread.start()

        # Eingabeschleife
        try:
            while self.verbunden:
                eingabe = input(f"Du ({self.benutzername}): ")

                # Leere Eingaben ignorieren
                if not eingabe.strip():
                    continue

                # Befehle verarbeiten
                if eingabe.strip().lower() == '/quit':
                    print("[INFO] Chat wird beendet...")
                    self._verbindung_beenden()
                    break
                elif eingabe.strip().lower() == '/info':
                    self._info_anzeigen()
                    continue

                # Nachricht senden
                self.nachricht_senden(eingabe)

        except (KeyboardInterrupt, EOFError):
            print("\n[INFO] Chat wird beendet...")
            self._verbindung_beenden()

    def _verbindung_beenden(self):
        """Sendet eine Abschiedsnachricht und beendet die Verbindung ordnungsgemäß."""
        if self.verbunden:
            tschuess = FluesternetzPaket(
                typ=NachrichtenTyp.TSCHUESS,
                nutzlast=f"{self.benutzername} hat den Chat verlassen.".encode('utf-8'),
                sequenz=self._naechste_sequenz()
            )
            self._senden(tschuess)
            self.verbunden = False

    def _info_anzeigen(self):
        """Zeigt Informationen über die aktuelle Verbindung an."""
        print(f"\n--- Verbindungsinformationen ---")
        print(f"  Protokoll: FlüsterNetz v{PROTOKOLL_VERSION}")
        print(f"  Partner: {self.partner_name}")
        print(f"  TLS-Version: {self.tls_socket.version() if self.tls_socket else 'Keine'}")
        print(f"  HMAC-Schlüssel: {'Aktiv' if self.hmac_schluessel else 'Nicht gesetzt'}")
        print(f"  Sequenzzähler: {self.sequenz_zaehler}")
        print(f"-------------------------------\n")

    def _aufraeumen(self):
        """Schließt alle offenen Verbindungen und räumt Ressourcen auf."""
        self.verbunden = False
        self.beenden_ereignis.set()

        if self.tls_socket:
            try:
                self.tls_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.tls_socket.close()

        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.socket.close()


# ============================================================
# Hauptprogramm
# ============================================================

def hauptprogramm():
    """
    Einstiegspunkt des FlüsterNetz-Chatprogramms.
    Verarbeitet Kommandozeilenargumente und startet den Chat.
    """
    # Argument-Parser konfigurieren
    parser = argparse.ArgumentParser(
        description='FlüsterNetz - Sicheres P2P-Chatprotokoll',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Beispiele:
  Server starten:    python3 fluesternetz.py server -n Alice
  Client verbinden:  python3 fluesternetz.py client -z 192.168.1.100 -n Bob
  Anderer Port:      python3 fluesternetz.py server -n Alice -p 9778
        """
    )

    # Unterbefehle für Server/Client-Modus
    unterbefehle = parser.add_subparsers(dest='modus', help='Betriebsmodus')
    unterbefehle.required = True

    # Server-Modus Argumente
    server_parser = unterbefehle.add_parser('server', help='Als Server starten (auf Verbindung warten)')
    server_parser.add_argument('-n', '--name', default='Anonym', help='Benutzername (Standard: Anonym)')
    server_parser.add_argument('-p', '--port', type=int, default=PROTOKOLL_PORT,
                               help=f'Port (Standard: {PROTOKOLL_PORT})')

    # Client-Modus Argumente
    client_parser = unterbefehle.add_parser('client', help='Als Client verbinden')
    client_parser.add_argument('-z', '--ziel', required=True, help='IP-Adresse des Servers')
    client_parser.add_argument('-n', '--name', default='Anonym', help='Benutzername (Standard: Anonym)')
    client_parser.add_argument('-p', '--port', type=int, default=PROTOKOLL_PORT,
                               help=f'Port (Standard: {PROTOKOLL_PORT})')

    # Argumente parsen
    argumente = parser.parse_args()

    # Chat-Instanz erstellen und starten
    chat = FluesternetzChat(benutzername=argumente.name)

    if argumente.modus == 'server':
        chat.als_server_starten(port=argumente.port)
    elif argumente.modus == 'client':
        chat.als_client_verbinden(
            ziel_adresse=argumente.ziel,
            port=argumente.port
        )


# Programm starten, wenn direkt ausgeführt
if __name__ == '__main__':
    hauptprogramm()
