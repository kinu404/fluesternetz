#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FlüsterNetz - P2P Chatprotokoll mit TLS-Verschlüsselung
Programmentwurf Network Security 2026 - DHBW

Autoren: Philipp Reich, Celil Sahin, Glenn Strommer,
         Lukas Gagstatter, Noah Vesenjak-Dolinsek
"""

# region Imports
import socket
import ssl
import threading
import struct
import hmac
import hashlib
import os
import time
import json
import argparse
import secrets
# endregion


# region Konstanten und Nachrichtentypen

PROTOKOLL_VERSION = 1
PROTOKOLL_PORT = 9777	# bei IANA nicht registriert, kein Konflikt bekannt
MAGISCHE_BYTES = b'\xF1\xCE'	# "FlüsterNetz Cipher Envelope"
MAX_NUTZLAST = 65535	# 2 Byte Längenfeld -> max 64 KiB


class NachrichtenTyp:
	"""Nachrichtentypen im FlüsterNetz-Protokoll (vgl. Whitepaper Abschnitt 4.1)"""
	HALLO = 0x01	# Verbindungsaufbau
	HALLO_ANTWORT = 0x02
	SCHLUESSEL = 0x03	# reserviert für spätere Erweiterung
	CHAT = 0x10
	BESTAETIGUNG = 0x11	# ACK
	HERZSCHLAG = 0x20	# Keep-Alive
	TSCHUESS = 0xF0	# Verbindungsabbau
	FEHLER = 0xFF

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
		return NachrichtenTyp.NAMEN.get(typ, f"UNBEKANNT(0x{typ:02X})")

# endregion


# region Paket-Klasse

class FluesternetzPaket:
	"""
	Ein FlüsterNetz-Protokollpaket.

	Header: Magic(2) | Version(1) | Typ(1) | Flags(1) | Seq(2) | Zeit(4) | Länge(2) | HMAC(32)
	Danach folgt die variable Nutzlast (0 bis 65535 Bytes).
	Gesamt-Header: 13 + 32 = 45 Bytes
	"""

	HEADER_FORMAT = '!2sBBBHIH'	# Network Byte Order
	HEADER_LAENGE = struct.calcsize(HEADER_FORMAT)	# 13 Bytes
	HMAC_LAENGE = 32
	GESAMT_HEADER = HEADER_LAENGE + HMAC_LAENGE	# 45 Bytes

	def __init__(self, typ, nutzlast=b'', sequenz=0, flags=0):
		self.magic = MAGISCHE_BYTES
		self.version = PROTOKOLL_VERSION
		self.typ = typ
		self.flags = flags
		self.sequenz = sequenz
		self.zeitstempel = int(time.time())
		self.nutzlast = nutzlast
		self.hmac_wert = b'\x00' * self.HMAC_LAENGE

	def packen(self, hmac_schluessel=None):
		"""Paket in Bytes serialisieren. Berechnet HMAC falls Schlüssel vorhanden."""
		if len(self.nutzlast) > MAX_NUTZLAST:
			raise ValueError(f"Nutzlast zu groß: {len(self.nutzlast)} Bytes")

		header = struct.pack(
			self.HEADER_FORMAT,
			self.magic, self.version, self.typ,
			self.flags, self.sequenz,
			self.zeitstempel, len(self.nutzlast)
		)

		# HMAC über Header + Nutzlast
		if hmac_schluessel:
			self.hmac_wert = hmac.new(
				hmac_schluessel, header + self.nutzlast, hashlib.sha256
			).digest()
		else:
			self.hmac_wert = b'\x00' * self.HMAC_LAENGE

		return header + self.hmac_wert + self.nutzlast

	@classmethod
	def entpacken(cls, daten, hmac_schluessel=None):
		"""Bytes deserialisieren und HMAC prüfen. Gibt None bei Fehler."""
		# erstmal schauen ob genug Daten da sind
		if len(daten) < cls.GESAMT_HEADER:
			print(f"[FEHLER] Paket zu kurz: {len(daten)} Bytes")
			return None

		header_roh = daten[:cls.HEADER_LAENGE]
		magic, version, typ, flags, sequenz, zeit, laenge = struct.unpack(
			cls.HEADER_FORMAT, header_roh
		)

		# Magic Bytes prüfen. Wenn die nicht stimmen ist es kein FlüsterNetz-Paket
		if magic != MAGISCHE_BYTES:
			print(f"[FEHLER] Falsche Magic Bytes: 0x{magic.hex()}")
			return None

		if version != PROTOKOLL_VERSION:
			print(f"[WARNUNG] Unbekannte Protokollversion: {version}")

		hmac_empfangen = daten[cls.HEADER_LAENGE:cls.GESAMT_HEADER]
		nutzlast = daten[cls.GESAMT_HEADER:cls.GESAMT_HEADER + laenge]

		# defensive Prüfung "haben wir wirklich so viele Bytes wie im Header angegeben"?
		if len(nutzlast) < laenge:
			print(f"[FEHLER] Nutzlast unvollständig: erwartet {laenge}, bekommen {len(nutzlast)}")
			return None

		# HMAC verifizieren
		if hmac_schluessel:
			hmac_erwartet = hmac.new(
				hmac_schluessel, header_roh + nutzlast, hashlib.sha256
			).digest()
			if not hmac.compare_digest(hmac_empfangen, hmac_erwartet):
				print("[FEHLER] HMAC ungültig - Paket möglicherweise manipuliert!")
				return None

		paket = cls(typ=typ, nutzlast=nutzlast, sequenz=sequenz, flags=flags)
		paket.version = version
		paket.zeitstempel = zeit
		paket.hmac_wert = hmac_empfangen
		return paket

	def __str__(self):
		typ_name = NachrichtenTyp.name_von(self.typ)
		return (f"[FlüsterNetz v{self.version}] {typ_name} "
			f"Seq={self.sequenz} Flags=0x{self.flags:02X} "
			f"Nutzlast={len(self.nutzlast)}B")

# endregion


# region Chat-Klasse

class FluesternetzChat:
	"""Hauptklasse für den FlüsterNetz P2P-Chat."""

	def __init__(self, benutzername="Anonym"):
		self.benutzername = benutzername
		self.verbunden = False
		self.socket = None
		self.tls_socket = None
		self.sequenz_zaehler = 0
		self.hmac_schluessel = None	# wird beim Handshake gesetzt
		self.empfangs_thread = None
		self.partner_name = ""
		self.beenden_event = threading.Event()

	def _naechste_sequenz(self):
		"""Sequenznummer hochzählen, 16 Bit mit Überlauf."""
		self.sequenz_zaehler = (self.sequenz_zaehler + 1) % 65536
		return self.sequenz_zaehler

	# --- TLS ---

	def _tls_kontext_erstellen(self, ist_server=False):
		"""TLS-Kontext mit mindestens TLS 1.2 erstellen."""
		if ist_server:
			ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		else:
			ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
			# Selbstsigniert -> keine CA-Prüfung möglich.
			# Wir zeigen stattdessen den Fingerprint an (TOFU, wie bei SSH)
			ctx.check_hostname = False
			ctx.verify_mode = ssl.CERT_NONE

		ctx.minimum_version = ssl.TLSVersion.TLSv1_2
		return ctx

	def _zertifikate_erstellen(self):
		"""Selbstsigniertes TLS-Zertifikat generieren (RSA 2048)."""
		# Imports hier lokal weil wir die nur auf der Server-Seite brauchen
		from cryptography import x509
		from cryptography.x509.oid import NameOID
		from cryptography.hazmat.primitives import hashes, serialization
		from cryptography.hazmat.primitives.asymmetric import rsa
		import datetime

		schluessel = rsa.generate_private_key(
			public_exponent=65537,
			key_size=2048,
		)

		# Zertifikatsname - DHBW damit man sieht woher es kommt
		name = x509.Name([
			x509.NameAttribute(NameOID.COMMON_NAME, "FlüsterNetz"),
			x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DHBW Programmentwurf"),
		])

		jetzt = datetime.datetime.now(datetime.timezone.utc)
		zertifikat = (
			x509.CertificateBuilder()
			.subject_name(name)
			.issuer_name(name)
			.public_key(schluessel.public_key())
			.serial_number(x509.random_serial_number())
			.not_valid_before(jetzt)
			.not_valid_after(jetzt + datetime.timedelta(days=1))	# reicht für eine Sitzung
			.sign(schluessel, hashes.SHA256())
		)

		# temp-Dateien, werden später wieder gelöscht
		key_pfad = "/tmp/fluesternetz_key.pem"
		cert_pfad = "/tmp/fluesternetz_cert.pem"

		with open(key_pfad, "wb") as f:
			f.write(schluessel.private_bytes(
				serialization.Encoding.PEM,
				serialization.PrivateFormat.TraditionalOpenSSL,
				serialization.NoEncryption()
			))
		with open(cert_pfad, "wb") as f:
			f.write(zertifikat.public_bytes(serialization.Encoding.PEM))

		return cert_pfad, key_pfad

	def _fingerprint_anzeigen(self):
		"""
		SHA-256 Fingerprint des Peer-Zertifikats ausgeben.
		Damit kann man prüfen ob man wirklich mit dem richtigen
		Partner verbunden ist und kein MITM dazwischen sitzt.
		Gleiche Idee wie bei SSH beim ersten Verbinden.
		"""
		cert_bin = self.tls_socket.getpeercert(binary_form=True)
		if not cert_bin:
			print("[TLS] Kein Zertifikat vom Partner erhalten")
			return
		fp = hashlib.sha256(cert_bin).hexdigest()
		fp_fmt = ':'.join(fp[i:i+2] for i in range(0, len(fp), 2))
		print(f"[TLS] Zertifikats-Fingerprint:")
		print(f"      {fp_fmt}")
		print("[TLS] Bitte mit dem Partner vergleichen!")

	# --- Senden und Empfangen ---

	def _senden(self, paket):
		"""Paket mit 4-Byte Längen-Prefix senden (Framing)."""
		sock = self.tls_socket or self.socket
		if not sock:
			return
		try:
			daten = paket.packen(self.hmac_schluessel)
			# Länge vorweg damit der Empfänger weiß wie viel er lesen muss
			sock.sendall(struct.pack('!I', len(daten)) + daten)
		except (BrokenPipeError, ConnectionResetError, OSError) as e:
			print(f"\n[FEHLER] Senden fehlgeschlagen: {e}")
			self.verbunden = False

	def _empfangen(self, sock):
		"""Komplettes Paket lesen: erst Länge (4 Byte), dann Daten."""
		try:
			laenge_roh = self._recv_exact(sock, 4)
			if not laenge_roh:
				return None
			paket_laenge = struct.unpack('!I', laenge_roh)[0]

			# Plausibilitätsprüfung damit uns niemand riesige Pakete unterjubelt
			max_erlaubt = MAX_NUTZLAST + FluesternetzPaket.GESAMT_HEADER
			if paket_laenge > max_erlaubt:
				print(f"[FEHLER] Paketgröße überschreitet Limit: {paket_laenge}")
				return None

			daten = self._recv_exact(sock, paket_laenge)
			if not daten:
				return None

			return FluesternetzPaket.entpacken(daten, self.hmac_schluessel)
		except (ConnectionResetError, OSError):
			return None

	def _recv_exact(self, sock, n):
		"""Exakt n Bytes lesen. None bei Abbruch."""
		buf = b''
		while len(buf) < n:
			try:
				chunk = sock.recv(n - len(buf))
				if not chunk:
					return None
				buf += chunk
			except (ConnectionResetError, OSError):
				return None
		return buf

	# --- Handshake (vgl. Sequenzdiagramm Phase 3) ---

	def _handshake(self, ist_server, sock):
		"""
		Benutzernamen austauschen und HMAC-Schlüssel vereinbaren.
		Der Schlüssel wird innerhalb des TLS-Tunnels übertragen.
		"""
		if ist_server:
			paket = self._empfangen(sock)
			if not paket or paket.typ != NachrichtenTyp.HALLO:
				raise ConnectionError("Kein gültiges HALLO empfangen")

			client_info = json.loads(paket.nutzlast.decode('utf-8'))
			self.partner_name = client_info.get('benutzername', 'Unbekannt')
			print(f"[INFO] Anfrage von: {self.partner_name}")

			# 32 Byte = 256 Bit HMAC-Schlüssel
			self.hmac_schluessel = secrets.token_bytes(32)

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
			# noch ohne HMAC weil der Partner den Schlüssel erst mit dieser Nachricht bekommt
			self._senden_raw(sock, antwort)

		else:
			hallo_daten = json.dumps({
				'benutzername': self.benutzername,
				'version': PROTOKOLL_VERSION,
			}).encode('utf-8')

			hallo = FluesternetzPaket(
				typ=NachrichtenTyp.HALLO,
				nutzlast=hallo_daten,
				sequenz=self._naechste_sequenz()
			)
			self._senden_raw(sock, hallo)

			paket = self._empfangen(sock)
			if not paket or paket.typ != NachrichtenTyp.HALLO_ANTWORT:
				raise ConnectionError("Keine gültige HALLO_ANTWORT")

			server_info = json.loads(paket.nutzlast.decode('utf-8'))
			self.partner_name = server_info.get('benutzername', 'Unbekannt')

			if server_info.get('status') != 'akzeptiert':
				raise ConnectionError("Verbindung vom Server abgelehnt")

			self.hmac_schluessel = bytes.fromhex(server_info['hmac_schluessel'])

		print(f"[INFO] Handshake abgeschlossen mit {self.partner_name}")
		self.verbunden = True

	def _senden_raw(self, sock, paket):
		"""Paket direkt über einen bestimmten Socket schicken (für Handshake)."""
		daten = paket.packen(self.hmac_schluessel)
		sock.sendall(struct.pack('!I', len(daten)) + daten)

	# --- Nachrichtenverarbeitung ---

	def _empfangs_schleife(self):
		"""Läuft im Hintergrund-Thread, verarbeitet eingehende Pakete."""
		sock = self.tls_socket if self.tls_socket else self.socket

		while self.verbunden and not self.beenden_event.is_set():
			paket = self._empfangen(sock)
			if paket is None:
				if self.verbunden:
					print(f"\n[INFO] Verbindung zu {self.partner_name} verloren.")
					self.verbunden = False
				break
			self._paket_verarbeiten(paket)

	def _paket_verarbeiten(self, paket):
		"""Eingehendes Paket je nach Typ behandeln."""
		if paket.typ == NachrichtenTyp.CHAT:
			nachricht = paket.nutzlast.decode('utf-8')
			zeit = time.strftime('%H:%M:%S', time.localtime(paket.zeitstempel))
			print(f"\n[{zeit}] {self.partner_name}: {nachricht}")
			print(f"Du ({self.benutzername}): ", end='', flush=True)

			# ACK senden
			ack = FluesternetzPaket(
				typ=NachrichtenTyp.BESTAETIGUNG,
				nutzlast=struct.pack('!H', paket.sequenz),
				sequenz=self._naechste_sequenz()
			)
			self._senden(ack)

		elif paket.typ == NachrichtenTyp.BESTAETIGUNG:
			pass	# TODO: evtl. unbestätigte Nachrichten tracken

		elif paket.typ == NachrichtenTyp.HERZSCHLAG:
			self._senden(FluesternetzPaket(
				typ=NachrichtenTyp.HERZSCHLAG,
				sequenz=self._naechste_sequenz()
			))

		elif paket.typ == NachrichtenTyp.TSCHUESS:
			print(f"\n[INFO] {self.partner_name} hat den Chat verlassen.")
			self.verbunden = False

		elif paket.typ == NachrichtenTyp.FEHLER:
			try:
				msg = paket.nutzlast.decode('utf-8')
			except UnicodeDecodeError:
				msg = "(nicht lesbar)"
			print(f"\n[FEHLER vom Partner] {msg}")

		else:
			print(f"\n[WARNUNG] Unbekannter Typ: {NachrichtenTyp.name_von(paket.typ)}")

	def nachricht_senden(self, text):
		"""Chat-Nachricht an den Partner schicken."""
		if not self.verbunden:
			print("[FEHLER] Nicht verbunden.")
			return

		encoded = text.encode('utf-8')
		if len(encoded) > MAX_NUTZLAST:
			print(f"[FEHLER] Nachricht zu lang ({len(encoded)} Bytes)")
			return

		paket = FluesternetzPaket(
			typ=NachrichtenTyp.CHAT,
			nutzlast=encoded,
			sequenz=self._naechste_sequenz(),
			flags=0x01	# Bit 0 = über TLS verschlüsselt
		)
		self._senden(paket)

	# --- Server-Modus ---

	def als_server_starten(self, port=PROTOKOLL_PORT):
		"""Im Server-Modus auf eingehende Verbindung warten."""
		print(f"-- FlüsterNetz Server --")
		print(f"Benutzer: {self.benutzername}")
		print(f"Port:     {port}")
		print()

		cert_pfad, key_pfad = self._zertifikate_erstellen()
		print("[INFO] TLS-Zertifikat erstellt")

		srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		srv.bind(('0.0.0.0', port))
		srv.listen(1)	# P2P, nur eine Verbindung

		print(f"[INFO] Warte auf Verbindung...")

		try:
			client_sock, addr = srv.accept()
			print(f"[INFO] Verbindung von {addr[0]}:{addr[1]}")

			tls_ctx = self._tls_kontext_erstellen(ist_server=True)
			tls_ctx.load_cert_chain(cert_pfad, key_pfad)
			self.tls_socket = tls_ctx.wrap_socket(client_sock, server_side=True)
			self.socket = client_sock
			print(f"[INFO] TLS hergestellt: {self.tls_socket.version()}")

			self._handshake(ist_server=True, sock=self.tls_socket)
			self._chat_schleife()

		except KeyboardInterrupt:
			print("\n[INFO] Server beendet.")
		except Exception as e:
			print(f"[FEHLER] {e}")
		finally:
			self._aufraeumen()
			srv.close()
			for p in (cert_pfad, key_pfad):
				if os.path.exists(p):
					os.remove(p)

	# --- Client-Modus ---

	def als_client_verbinden(self, ziel, port=PROTOKOLL_PORT):
		"""Im Client-Modus mit einem Server verbinden."""
		print(f"-- FlüsterNetz Client --")
		print(f"Benutzer: {self.benutzername}")
		print(f"Ziel:     {ziel}:{port}")
		print()

		try:
			self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self.socket.connect((ziel, port))
			print(f"[INFO] TCP-Verbindung hergestellt")

			tls_ctx = self._tls_kontext_erstellen(ist_server=False)
			self.tls_socket = tls_ctx.wrap_socket(self.socket, server_hostname=ziel)
			print(f"[INFO] TLS hergestellt: {self.tls_socket.version()}")

			# Fingerprint anzeigen damit man prüfen kann ob kein MITM dazwischen ist
			self._fingerprint_anzeigen()

			self._handshake(ist_server=False, sock=self.tls_socket)
			self._chat_schleife()

		except ConnectionRefusedError:
			print(f"[FEHLER] Verbindung zu {ziel}:{port} abgelehnt")
		except KeyboardInterrupt:
			print("\n[INFO] Verbindung beendet.")
		except Exception as e:
			print(f"[FEHLER] {e}")
		finally:
			self._aufraeumen()

	# --- Chat-Schleife ---

	def _chat_schleife(self):
		"""Empfangs-Thread starten und Benutzereingaben verarbeiten."""
		print()
		print(f"Chat mit {self.partner_name} gestartet. /quit zum Beenden, /info für Details.")
		print()

		self.empfangs_thread = threading.Thread(
			target=self._empfangs_schleife,
			daemon=True,
			name="Empfang"
		)
		self.empfangs_thread.start()

		try:
			while self.verbunden:
				eingabe = input(f"Du ({self.benutzername}): ")
				cmd = eingabe.strip().lower()

				if not cmd:
					continue
				if cmd == '/quit':
					print("[INFO] Chat wird beendet...")
					self._verbindung_beenden()
					break
				elif cmd == '/info':
					self._info_anzeigen()
				else:
					self.nachricht_senden(eingabe)

		except (KeyboardInterrupt, EOFError):
			print("\n[INFO] Chat wird beendet...")
			self._verbindung_beenden()

	def _verbindung_beenden(self):
		"""TSCHUESS senden und Verbindung trennen."""
		if not self.verbunden:
			return
		tschuess = FluesternetzPaket(
			typ=NachrichtenTyp.TSCHUESS,
			nutzlast=f"{self.benutzername} hat den Chat verlassen.".encode('utf-8'),
			sequenz=self._naechste_sequenz()
		)
		self._senden(tschuess)
		self.verbunden = False

	def _info_anzeigen(self):
		"""Verbindungsdetails ausgeben."""
		tls_ver = self.tls_socket.version() if self.tls_socket else "keine"
		print(f"\n--- Verbindungsinfo ---")
		print(f"Protokoll: FlüsterNetz v{PROTOKOLL_VERSION}")
		print(f"Partner:   {self.partner_name}")
		print(f"TLS:       {tls_ver}")
		print(f"HMAC:      {'aktiv' if self.hmac_schluessel else 'nicht gesetzt'}")
		print(f"Sequenz:   {self.sequenz_zaehler}")
		print(f"-----------------------\n")

	def _aufraeumen(self):
		"""Sockets schließen und alles sauber beenden."""
		self.verbunden = False
		self.beenden_event.set()

		for sock in (self.tls_socket, self.socket):
			if sock:
				try:
					sock.shutdown(socket.SHUT_RDWR)
				except OSError:
					pass
				sock.close()

# endregion


# region Hauptprogramm

def hauptprogramm():
	"""Kommandozeilenargumente verarbeiten und Chat starten."""
	parser = argparse.ArgumentParser(
		description='FlüsterNetz - Sicheres P2P-Chatprotokoll',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog="""Beispiele:
  Server:  python3 fluesternetz.py server -n Alice
  Client:  python3 fluesternetz.py client -z 10.0.0.1 -n Bob"""
	)

	sub = parser.add_subparsers(dest='modus', help='Betriebsmodus')
	sub.required = True

	# Server-Argumente
	sp = sub.add_parser('server', help='Auf Verbindung warten')
	sp.add_argument('-n', '--name', default='Anonym', help='Benutzername')
	sp.add_argument('-p', '--port', type=int, default=PROTOKOLL_PORT, help='Port')

	# Client-Argumente
	cp = sub.add_parser('client', help='Mit Server verbinden')
	cp.add_argument('-z', '--ziel', required=True, help='Server-IP')
	cp.add_argument('-n', '--name', default='Anonym', help='Benutzername')
	cp.add_argument('-p', '--port', type=int, default=PROTOKOLL_PORT, help='Port')

	args = parser.parse_args()
	chat = FluesternetzChat(benutzername=args.name)

	if args.modus == 'server':
		chat.als_server_starten(port=args.port)
	else:
		chat.als_client_verbinden(ziel=args.ziel, port=args.port)


if __name__ == '__main__':
	hauptprogramm()

# endregion
