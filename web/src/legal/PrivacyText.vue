<!-- Copyright 2026 Simon Ostendorf -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

<script setup lang="ts">
import { useLanguage } from '@ostendorf-cloud/govue'

// The privacy text of burnlink, written from what the code and the repository
// documents state: internal/store, internal/webapp/secrets,
// internal/webapp/requestlink, docs/concepts/burnlink.md, the README section
// "Page view counting" and the "What is counted" card of SecurityView.vue.
// German and English say the same. A change to what the server stores, logs or
// counts changes this text in the same commit.
const { locale } = useLanguage()
</script>

<template>
  <div v-if="locale === 'de'" class="flex flex-col gap-4 text-text" data-testid="privacy-de">
    <h2 class="text-xl font-semibold text-text">Verantwortlicher</h2>
    <p>
      Simon Ostendorf, Frankenstr. 8, 52070 Aachen, Deutschland<br />
      E-Mail:
      <a class="text-accent-text hover:underline" href="mailto:info@burnlink.de">info@burnlink.de</a
      ><br />
      Telefon:
      <a class="text-accent-text hover:underline" href="tel:+4915730971784">+49 1573 0971784</a>
    </p>

    <h2 class="text-xl font-semibold text-text">Was burnlink ist</h2>
    <p>
      burnlink gibt ein Geheimnis über einen Link weiter, der es genau einmal ausliefert. Es gibt
      kein Konto und keine Anmeldung. Wie die Verschlüsselung funktioniert und welche Teile heute
      schon laufen, steht auf der
      <a class="text-accent-text hover:underline" href="/security">Sicherheitsseite</a>. Dieser Text
      wiederholt sie nicht.
    </p>

    <h2 class="text-xl font-semibold text-text">Was der Server nie erhält</h2>
    <p>
      Der Browser verschlüsselt ein Geheimnis mit der Web-Crypto-Schnittstelle, bevor etwas
      hochgeladen wird. Der Schlüssel steht in dem Teil des Links nach dem Zeichen #. Ein Browser
      sendet diesen Teil nicht an einen Server. Der Server erhält deshalb weder einen Schlüssel noch
      einen Klartext, auch keine Passphrase, keinen Dateinamen und keinen Dateiinhalt.
    </p>

    <h2 class="text-xl font-semibold text-text">Was gespeichert wird</h2>
    <ul class="flex list-disc flex-col gap-2 pl-5">
      <li>
        Die verschlüsselten Daten genau so, wie sie ankamen, eine zufällige Kennung und der
        Zeitpunkt des Ablaufs. Der Server kann die Daten nicht entschlüsseln.
      </li>
      <li>Gespeichert wird in einem Redis-kompatiblen Speicher (Valkey), der zum Dienst gehört.</li>
      <li>
        Nur wenn der Absender eine Benachrichtigung wünscht: die von ihm eingegebene
        Webhook-Adresse, im Klartext, unter derselben Kennung und mit derselben Lebensdauer wie das
        Geheimnis. Der Server kann diese Adresse lesen. Sie kann personenbezogene Daten enthalten.
        Sie wird beim ersten Öffnen gelöscht, spätestens mit dem Ablauf. Beim ersten Öffnen sendet
        der Server genau eine Anfrage an diese Adresse, mit der Kennung des Links und dem Zeitpunkt
        des Öffnens, nie mit dem Geheimnis. Bei einem Fehler wiederholt er sie höchstens zweimal.
        Die Adresse wird nicht protokolliert. Der Empfänger der Anfrage ist der Betreiber des vom
        Absender gewählten Dienstes.
      </li>
    </ul>

    <h2 class="text-xl font-semibold text-text">Wie lange</h2>
    <ul class="flex list-disc flex-col gap-2 pl-5">
      <li>
        Beim ersten Öffnen wird ein Geheimnis in demselben Schritt ausgeliefert und gelöscht. Ein
        zweiter Abruf erhält nichts.
      </li>
      <li>
        Wird es nicht geöffnet, läuft es mit seiner Lebensdauer ab. Der Absender wählt sie innerhalb
        der Grenzen, die der Betreiber einstellt. Ohne andere Einstellung liegen diese bei einer
        Minute bis sieben Tagen, und ohne Wahl gelten 24 Stunden. Mehr als 30 Tage lässt der Dienst
        nicht zu.
      </li>
      <li>
        Abgelaufene und geöffnete Geheimnisse sind nicht zu unterscheiden. Nichts zeichnet auf,
        welches Geheimnis geöffnet wurde: Das Protokoll (siehe unten) enthält das Routenmuster, nie
        die Kennung.
      </li>
    </ul>

    <h2 class="text-xl font-semibold text-text">Protokoll des Servers</h2>
    <p>
      Der Server schreibt für jede Anfrage eine Protokollzeile: Methode, das Routenmuster (nicht der
      Pfad, also nie die Kennung eines Links), Statuscode, Größe der Antwort, Dauer und die Adresse,
      von der die Anfrage kam. Jede Zeile trägt außerdem den Zeitpunkt und eine zufällige
      Anfragekennung. Auch das Öffnen eines Geheimnisses schreibt eine solche Zeile, ohne dessen
      Kennung. Mit dieser Adresse begrenzt der Server außerdem, wie viele Anfragen ein Client
      stellen darf.
    </p>

    <h2 class="text-xl font-semibold text-text">Zählung der Seitenaufrufe</h2>
    <p>
      Wenn der Betreiber sie eingeschaltet hat, zählt der Server Seitenaufrufe und meldet sie nach
      der Auslieferung der Seite an Umami, ein Statistikwerkzeug. In Ihrem Browser läuft dafür
      nichts, und es wird kein Cookie gesetzt. Richtet der Betreiber sie nicht ein, ist die Zählung
      aus.
    </p>
    <ul class="flex list-disc flex-col gap-2 pl-5">
      <li>
        Gezählt wird das Routenmuster der Seite, zum Beispiel
        <code class="font-mono">/security</code>,
        <code class="font-mono">/s/&#123;id&#125;</code> oder
        <code class="font-mono">/r/&#123;id&#125;</code>. Jeder Link zu einem Geheimnis ist der eine
        Eintrag <code class="font-mono">/s/&#123;id&#125;</code> und jeder Anfrage-Link der eine
        Eintrag <code class="font-mono">/r/&#123;id&#125;</code>, nie die Kennung. Das Laden der
        Seite hinter einem Link zu einem Geheimnis wird als Seitenaufruf gezählt, das Öffnen des
        Geheimnisses nicht.
      </li>
      <li>
        Mitgesendet werden der Hostname der Seite, die erste Sprache, die Ihr Browser anfragt, Ihr
        Browser und System als User-Agent, der Ursprung (Schema und Host, ohne Pfad) der Seite, von
        der Sie kamen, und Ihre Adresse ohne ihren letzten Teil: bei IPv4 die ersten drei von vier
        Zahlen, bei IPv6 die ersten 48 Bit. Umami leitet daraus Land, Region und Stadt ab.
      </li>
      <li>
        Nicht gezählt werden die Kennung eines Links, der Schlüssel hinter dem #, eine
        Query-Zeichenfolge, alles unter <code class="font-mono">/api</code>, Dateien, die die Seite
        lädt, und die Health- und Metrik-Routen. Das Öffnen eines Geheimnisses ist kein Ereignis.
      </li>
      <li>
        Gar nicht gezählt werden Besucher, die Do Not Track oder Global Privacy Control senden,
        Prefetch-Anfragen, Bots und Clients mit privater Adresse.
      </li>
    </ul>

    <h2 class="text-xl font-semibold text-text">Cookies und Speicher im Browser</h2>
    <p>
      Diese Seite setzt kein Cookie und lädt kein Skript von einer anderen Seite. Ihr Browser kann
      eine Anzeigewahl (hell oder dunkel, Sprache) in seinem lokalen Speicher behalten. Sie wird
      nicht an den Server gesendet. Darüber hinaus legt diese Seite heute nichts im Speicher Ihres
      Browsers ab. Ein Geheimnis, sein Klartext, der Schlüssel und eine Passphrase bleiben nur im
      Arbeitsspeicher der geöffneten Seite und werden nirgends gespeichert. Beim Verlassen der Seite
      löscht sie diese Inhalte aus dem Arbeitsspeicher. Nach dem Öffnen entfernt die Seite den
      Schlüssel aus der Adresszeile. Der Link selbst steht in der Zwischenablage, und Ihr Browser
      zeichnet ihn beim Laden der Seite samt Schlüssel in seinem Verlauf auf. Das Entfernen aus der
      Adresszeile löscht diesen Verlaufseintrag nicht. Ein noch nicht geöffneter Link kann daher von
      jemandem mit Zugriff auf Ihren Browser geöffnet werden.
    </p>

    <h2 class="text-xl font-semibold text-text">Ihre Rechte</h2>
    <p>
      Sie haben nach der Datenschutz-Grundverordnung das Recht auf Auskunft, Berichtigung, Löschung,
      Einschränkung der Verarbeitung, Datenübertragbarkeit und Widerspruch, soweit die jeweilige
      Voraussetzung vorliegt. Schreiben Sie dafür an die oben genannte E-Mail-Adresse. Sie haben
      außerdem das Recht, sich bei einer Datenschutz-Aufsichtsbehörde zu beschweren.
    </p>
  </div>

  <div v-else class="flex flex-col gap-4 text-text" data-testid="privacy-en">
    <p class="text-text-muted">
      The German text is the legally binding one.
      <a class="text-accent-text hover:underline" href="/de/privacy">Read the German version</a>
    </p>

    <h2 class="text-xl font-semibold text-text">Controller</h2>
    <p>
      Simon Ostendorf, Frankenstr. 8, 52070 Aachen, Germany<br />
      Email:
      <a class="text-accent-text hover:underline" href="mailto:info@burnlink.de">info@burnlink.de</a
      ><br />
      Phone:
      <a class="text-accent-text hover:underline" href="tel:+4915730971784">+49 1573 0971784</a>
    </p>

    <h2 class="text-xl font-semibold text-text">What burnlink is</h2>
    <p>
      burnlink passes a secret on through a link that hands it out exactly once. There is no account
      and no sign-in. How the encryption works, and which parts already run today, is on the
      <a class="text-accent-text hover:underline" href="/security">security page</a>. This text does
      not repeat it.
    </p>

    <h2 class="text-xl font-semibold text-text">What the server never receives</h2>
    <p>
      The browser encrypts a secret with the Web Crypto interface before anything is uploaded. The
      key sits in the part of the link after the # character. A browser does not send that part to a
      server. The server therefore receives neither a key nor a plaintext, and no passphrase, file
      name or file content either.
    </p>

    <h2 class="text-xl font-semibold text-text">What is stored</h2>
    <ul class="flex list-disc flex-col gap-2 pl-5">
      <li>
        The encrypted data exactly as it arrived, a random id and the time of expiry. The server
        cannot decrypt the data.
      </li>
      <li>It is stored in a Redis compatible store (Valkey) that belongs to the service.</li>
      <li>
        Only if the sender asks for a notification: the webhook address the sender entered, in plain
        text, under the same id and with the same lifetime as the secret. The server can read this
        address. It may contain personal data. It is deleted when the secret is first opened, and at
        the latest when it expires. When the secret is first opened, the server sends exactly one
        request to that address, with the id of the link and the time it was opened, never the
        secret. On a failure it repeats the request at most twice. The address is not logged. The
        recipient of the request is the operator of the service the sender chose.
      </li>
    </ul>

    <h2 class="text-xl font-semibold text-text">For how long</h2>
    <ul class="flex list-disc flex-col gap-2 pl-5">
      <li>
        The first time a secret is opened, it is handed out and deleted in the same step. A second
        request gets nothing.
      </li>
      <li>
        If it is not opened, it expires with its lifetime. The sender chooses it within limits the
        operator configures. Unless set otherwise, the limits are one minute to seven days, and 24
        hours applies when none is chosen. The service allows no more than 30 days.
      </li>
      <li>
        An expired secret and an opened one cannot be told apart. Nothing records which secret was
        opened: the log (see below) carries the route pattern, never the id.
      </li>
    </ul>

    <h2 class="text-xl font-semibold text-text">Server log</h2>
    <p>
      For every request the server writes one log line: the method, the route pattern (not the path,
      so never the id of a link), the status code, the size of the answer, the duration and the
      address the request came from. Every line also carries the time and a random request id.
      Opening a secret writes such a line too, without its id. The server also uses the address to
      limit how many requests a client may make.
    </p>

    <h2 class="text-xl font-semibold text-text">Page view counting</h2>
    <p>
      If the operator has turned it on, the server counts page views and reports them to Umami, a
      statistics tool, after the page was served. Nothing runs in your browser for this, and no
      cookie is set. Unless the operator sets it up, the counting is off.
    </p>
    <ul class="flex list-disc flex-col gap-2 pl-5">
      <li>
        Counted is the route pattern of the page, for example
        <code class="font-mono">/security</code>,
        <code class="font-mono">/s/&#123;id&#125;</code> or
        <code class="font-mono">/r/&#123;id&#125;</code>. Every link to a secret is the one entry
        <code class="font-mono">/s/&#123;id&#125;</code> and every request link the one entry
        <code class="font-mono">/r/&#123;id&#125;</code>, never the id. Loading the page behind a
        link to a secret counts as a page view. Opening the secret does not.
      </li>
      <li>
        Sent with it are the site's host name, the first language your browser asks for, your
        browser and system as its user agent, the origin (scheme and host, no path) of the page that
        referred you, and your address without its last part: the first three of four numbers for
        IPv4, the first 48 bits for IPv6. Umami derives country, region and city from it.
      </li>
      <li>
        Not counted are the id of a link, the key after the #, a query string, anything under
        <code class="font-mono">/api</code>, files the page loads, and the health and metrics
        routes. Opening a secret is not an event.
      </li>
      <li>
        Not counted at all are visitors who send Do Not Track or Global Privacy Control, prefetch
        requests, bots and clients on a private address.
      </li>
    </ul>

    <h2 class="text-xl font-semibold text-text">Cookies and browser storage</h2>
    <p>
      This site sets no cookie and loads no script from another site. Your browser may keep a
      display choice (light or dark, language) in its local storage. It is not sent to the server.
      Beyond that, this site stores nothing in your browser's storage today. A secret, its
      plaintext, the key and a passphrase stay in the memory of the open page only and are saved
      nowhere. When you leave the page, it clears them from memory. After a reveal, the page removes
      the key from the address bar. The link itself is in your clipboard, and your browser records
      it with the key in its history when the page loads. Removing the key from the address bar does
      not delete that history entry, so someone with access to your browser can still open a link
      that was not revealed yet.
    </p>

    <h2 class="text-xl font-semibold text-text">Your rights</h2>
    <p>
      Under the General Data Protection Regulation you have the right to access, rectification,
      erasure, restriction of processing, data portability and objection, where the respective
      conditions are met. Write to the email address above. You also have the right to lodge a
      complaint with a data protection supervisory authority.
    </p>
  </div>
</template>
