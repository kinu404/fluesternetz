# Bekannte Limitierungen — FlüsterNetz

## 1. Nur Zwei-Teilnehmer-Kommunikation

FlüsterNetz ist als reines Peer-to-Peer-Protokoll für genau zwei Teilnehmer ausgelegt. Gruppenchats oder Mehrfachverbindungen werden nicht unterstützt. Für jeden zusätzlichen Chatpartner müsste eine separate Instanz gestartet werden.

## 2. Selbstsignierte TLS-Zertifikate

Beim Verbindungsaufbau werden automatisch selbstsignierte Zertifikate generiert. Es erfolgt keine Überprüfung der Zertifikatsauthentizität durch eine vertrauenswürdige Zertifizierungsstelle (CA). Dies macht das Protokoll anfällig für Man-in-the-Middle-Angriffe, bei denen ein Angreifer sich als Kommunikationspartner ausgeben könnte. In einer Produktivumgebung sollten CA-signierte Zertifikate oder ein Trust-on-First-Use (TOFU) Verfahren eingesetzt werden.

## 3. Kein Offline-Nachrichtenspeicher

Nachrichten werden nur an verbundene Teilnehmer zugestellt. Es gibt keinen Mechanismus, um Nachrichten für abwesende Teilnehmer zwischenzuspeichern. Wenn ein Teilnehmer nicht verbunden ist, gehen gesendete Nachrichten verloren.

## 4. Keine Persistente Identität

Benutzernamen werden bei jedem Verbindungsaufbau frei gewählt und sind nicht an eine kryptographische Identität gebunden. Ein Teilnehmer kann sich unter beliebigem Namen anmelden. Es gibt keine Registrierung oder Authentifizierung der Identität.

## 5. HMAC-Schlüsselaustausch

Der gemeinsame HMAC-Schlüssel wird im Klartext innerhalb des TLS-Tunnels übertragen. Obwohl TLS die Übertragung schützt, wäre ein Diffie-Hellman-Schlüsselaustausch auf Anwendungsebene eine robustere Lösung für Perfect Forward Secrecy auf Protokollebene.

## 6. Keine Dateiübertragung

Das Protokoll unterstützt ausschließlich Textnachrichten. Dateiübertragungen, Bilder, Multimedia-Inhalte oder andere binäre Daten werden nicht unterstützt.

## 7. Sequenznummer-Überlauf

Die Sequenznummer ist auf 16 Bit (0–65535) begrenzt. Nach 65536 Nachrichten beginnt der Zähler erneut bei 0. In extrem langen Sitzungen könnte dies theoretisch zu Verwechslungen bei der Nachrichtenzuordnung führen.

## 8. Keine Nachrichtenwiederholung bei Verlust

Obwohl TCP zuverlässige Übertragung gewährleistet, implementiert FlüsterNetz auf Anwendungsebene keine eigene Wiederholungslogik. Bei einer Unterbrechung der TCP-Verbindung gehen nicht bestätigte Nachrichten verloren.

## 9. Keine Zeitzonenbehandlung

Zeitstempel werden als Unix-Zeitstempel (UTC) gespeichert. Die Anzeige erfolgt in der lokalen Zeitzone des jeweiligen Rechners. Bei Teilnehmern in unterschiedlichen Zeitzonen können die angezeigten Uhrzeiten verwirrend wirken.

## 10. Einzelner TCP-Thread

Der Empfang von Nachrichten erfolgt in einem einzigen Thread. Bei sehr hoher Nachrichtenfrequenz könnte es zu Verzögerungen in der Darstellung kommen, da die Verarbeitung sequenziell erfolgt.

## 11. Keine Unterstützung für NAT-Traversal

FlüsterNetz benötigt eine direkte Netzwerkverbindung zwischen den Teilnehmern. Befinden sich beide hinter NAT-Routern, ist ohne Portweiterleitung oder einen Vermittlungsserver keine Verbindung möglich.
