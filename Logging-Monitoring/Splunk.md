BlueCoat, jetzt als Symantec Proxy bekannt, bietet detaillierte Web-Logs, die Informationen über den Web-Traffic eines Benutzers enthalten. Wenn Sie diese Logs in Splunk indexiert haben, können Sie verschiedene Panels erstellen, um Ihr Surfverhalten im Edge-Browser zu analysieren.

Hier sind einige Vorschläge für Panels und die entsprechenden SPLs, basierend auf den üblichen Feldern in BlueCoat-Logs:

---

### 1. Top besuchte Domains
```markdown
### Top besuchte Domains
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| top limit=10 cs_host
```

---

### 2. Tägliche Internetnutzung (nach Stunde)
```markdown
### Tägliche Internetnutzung
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| timechart span=1h count by cs_host
```

---

### 3. Kategorien von besuchten Websites
```markdown
### Kategorien von besuchten Websites
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| top limit=10 cs_categories
```

---

### 4. Volumen des heruntergeladenen Datenverkehrs
```markdown
### Volumen des heruntergeladenen Datenverkehrs
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| stats sum(sc_bytes) as TotalDownloaded 
```

---

### 5. Volumen des hochgeladenen Datenverkehrs
```markdown
### Volumen des hochgeladenen Datenverkehrs
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| stats sum(cs_bytes) as TotalUploaded 
```

---

### 6. Top Dateitypen, die heruntergeladen wurden
```markdown
### Top Dateitypen, die heruntergeladen wurden
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| top limit=10 cs_mime_type
```

---

### 7. Gesamtdauer der Internetnutzung
```markdown
### Gesamtdauer der Internetnutzung
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| stats sum(duration) as TotalDuration 
```

---

Bitte beachten Sie, dass die genauen Feldnamen und Werte in den SPLs von Ihrer spezifischen BlueCoat-Log-Konfiguration abhängen können. Die obigen SPLs sind allgemeine Beispiele und können Anpassungen erfordern, um korrekt zu funktionieren. Es ist auch wichtig zu beachten, dass der User-Agent-String für den Edge-Browser je nach Version variieren kann. Es könnte sinnvoll sein, die genauen User-Agent-Strings, die in Ihren Logs erscheinen, zu überprüfen und die SPLs entsprechend anzupassen.
