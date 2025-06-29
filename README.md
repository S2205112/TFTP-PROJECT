# TFTP Virtual Network Project

## Projektöversikt

Detta projekt syftar till att implementera och analysera ett **virtuellt LAN-nätverk**, inklusive utveckling av en **proxy-applikation** för att manipulera meddelanden som utbyts mellan klient och server med hjälp av **TFTP (Trivial File Transfer Protocol)**.

Genom att använda **VirtualBox** med förkonfigurerade **virtuella maskiner** (Debian), har vi skapat en miljö där vi kan förstå hur trafik flödar mellan olika värdar, hur man intercepterar och manipulerar paket, samt analysera protokollbeteende i praktiken.

---


## Lärandemål

Projektet fokuserar på följande lärandemål:

- Förstå grunderna i nätverkskommunikation inom ett LAN.
- Utveckla och implementera en proxy för trafikmanipulation mellan klient och server.
- Öka förståelsen för TFTP och dess tillförlitlighetsmekanismer ovanpå UDP.
- Analysera nätverkstrafik med **Wireshark**.
- Bygga praktiska färdigheter i **Python**. 

---

## Teknologistack

| Komponent          | Användning                                  |
|--------------------|----------------------------------------------|
| **Python**         | Implementation av proxy och trafikmanipulation |
| **TFTP (UDP 69)**  | Filsändning mellan klient och server         |
| **Wireshark**      | Trafikanalys                                |
| **VirtualBox**     | Skapande av isolerad virtuell nätverksmiljö  |
| **Linux (Debian) (VM)**    | Klient, Proxy och Server                     |
| **Visual Studio Code** | Kodredigering på klientmaskinen           |
| **SSH**            | Fjärranslutning och kontroll                 |

---

## Systemöversikt

Projektet består av tre huvudkomponenter inom ett virtuellt LAN:

- 🖥 **Klient (Debian)**: Innehåller TFTP-klient, SSH och kodredigerare. Initierar filöverföringar.
- 🔄 **Proxy**: Fångar upp och modifierar trafiken mellan klient och server. Utvecklad i Python.
- 🗄 **Server**: Kör TFTP-servern och svarar på klientens förfrågningar.

---

## Funktionalitet

- Implementering av **TFTP-filöverföring** via UDP
- Skapande av en **man-in-the-middle-proxy** för att:
  - Manipulera paketinnehåll
  - Simulera förlust av paket
  - Fördröja eller duplicera trafik
- Analys av trafikflöde och paket via **Wireshark**
- Simulering av **felhantering och återförsök** i TFTP

---

## 🛠️ Installation & Körning

1. Starta VirtualBox och kör de förkonfigurerade virtuella maskinerna: Klient, Proxy och Server.

2. På **klientmaskinen (Debian)**, öppna terminalen och kör följande kommandon:

```bash
sudo apt update
sudo apt install tftp tftpd -y
./run.sh
cd dk
sudo python3 template.py
```

3. När lösenord efterfrågas, skriv:  
```
dkproxy
```

4. Välj alternativ i listan:
```
Select an option: 
```

5. Initiera TFTP-filöverföring från klienten:

```bash
tftp <192.168.40.80>
```

I tftp-kommandotolken:

```tftp
get test512.txt
```


6. Öppna **Wireshark**, starta inspelning på rätt gränssnitt och använd filtren:

```
udp.port == 69
```
eller
```
tftp
```

för att analysera trafiken.

## Rapport

Läs hela projektbeskrivningen i [secureNetworkManagement.pdf](secureNetworkManagement.pdf).

## Team

Det här projektet utvecklades av:

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/LinneaKorneliussen">
        <img src="https://github.com/LinneaKorneliussen.png" width="100;" alt="Linnéa Korneliussen"/><br/>
        <sub><b>Linnéa Korneliussen</b></sub>
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/S2208913">
        <img src="https://github.com/S2208913.png" width="100;" alt="Clara Hansson"/><br/>
        <sub><b>Clara Hansson</b></sub>
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/Celinalinnerblom">
        <img src="https://github.com/Celinalinnerblom.png" width="100;" alt="Celina Linnerblom"/><br/>
        <sub><b>Celina Linnerblom</b></sub>
      </a>
    </td>
    <td align="center">
      <a href="https://github.com/S2205112">
        <img src="https://github.com/S2205112.png" width="100;" alt="Beata Jacobsson"/><br/>
        <sub><b>Beata Jacobsson</b></sub>
      </a>
    </td>
  </tr>
</table>
