# WinEventlog Statistics

### 1. Tägliche Übersicht
```spl
index=windows EventCode IN (4800,4801) 
| timechart span=1h count by EventCode
```

---

### 2. Mittagspause-Dauer
Angenommen, Ihre Mittagspause liegt zwischen 12:00 und 14:00 Uhr.
```spl
index=windows EventCode=4800 [search index=windows EventCode=4801 earliest=-1h@h latest=@h] 
| eval duration=(_time - relative_time(_time, "@h")) 
| stats avg(duration) as AvgPauseTime by date_mday, date_month

OR

index=windows (EventCode=4800 OR EventCode=4801) 
| fields _time, EventCode
| sort 0 _time
| streamstats window=1 previous(_time) as prev_time previous(EventCode) as prev_EventCode
| eval duration= if(EventCode=4801 AND prev_EventCode=4800, _time - prev_time, null())
| where isnotnull(duration)
| stats avg(duration) as AvgPauseTime by date_mday, date_month
```

---

### 3. Gesamte Pausenzeit
```spl
index=windows EventCode=4800 
| transaction startswith=EventCode="4800" endswith=EventCode="4801" 
| eval duration=(duration/60) 
| stats sum(duration) as TotalPauseTime by date_mday, date_month
```

---

### 4. Längste ununterbrochene Arbeitszeit
```spl
index=windows EventCode IN (4800,4801) 
| transaction startswith=EventCode="4801" endswith=EventCode="4800" 
| eval duration=(duration/60) 
| stats max(duration) as MaxWorkTime by date_mday, date_month
```

---

### 5. Häufigkeit von Pausen
```spl
index=windows EventCode=4800 
| stats count by date_mday, date_month
```

---

### 6. Vergleich Woche zu Woche
```spl
index=windows EventCode=4800 
| transaction startswith=EventCode="4800" endswith=EventCode="4801" 
| eval duration=(duration/60) 
| stats sum(duration) as TotalPauseTime by date_wday
```

---

### 7. Tageszeit vs. Pausendauer
```spl
index=windows EventCode=4800 
| transaction startswith=EventCode="4800" endswith=EventCode="4801" 
| eval duration=(duration/60), hour=strftime(_time, "%H") 
| stats avg(duration) as AvgPauseTime by hour
```

# Bluecoat logging

BlueCoat, jetzt als Symantec Proxy bekannt, bietet detaillierte Web-Logs, die Informationen über den Web-Traffic eines Benutzers enthalten. Wenn Sie diese Logs in Splunk indexiert haben, können Sie verschiedene Panels erstellen, um Ihr Surfverhalten im Edge-Browser zu analysieren.

Hier sind einige Vorschläge für Panels und die entsprechenden SPLs, basierend auf den üblichen Feldern in BlueCoat-Logs:

---

### 1. Top besuchte Domains

### Top besuchte Domains
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| top limit=10 cs_host
```

---

### 2. Tägliche Internetnutzung (nach Stunde)

### Tägliche Internetnutzung
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| timechart span=1h count by cs_host
```

---

### 3. Kategorien von besuchten Websites

### Kategorien von besuchten Websites
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| top limit=10 cs_categories
```

---

### 4. Volumen des heruntergeladenen Datenverkehrs

### Volumen des heruntergeladenen Datenverkehrs
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| stats sum(sc_bytes) as TotalDownloaded 
```

---

### 5. Volumen des hochgeladenen Datenverkehrs

### Volumen des hochgeladenen Datenverkehrs
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| stats sum(cs_bytes) as TotalUploaded 
```

---

### 6. Top Dateitypen, die heruntergeladen wurden

### Top Dateitypen, die heruntergeladen wurden
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| top limit=10 cs_mime_type
```

---

### 7. Gesamtdauer der Internetnutzung

### Gesamtdauer der Internetnutzung
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| stats sum(duration) as TotalDuration 
```

---

Bitte beachten Sie, dass die genauen Feldnamen und Werte in den SPLs von Ihrer spezifischen BlueCoat-Log-Konfiguration abhängen können. Die obigen SPLs sind allgemeine Beispiele und können Anpassungen erfordern, um korrekt zu funktionieren. Es ist auch wichtig zu beachten, dass der User-Agent-String für den Edge-Browser je nach Version variieren kann. Es könnte sinnvoll sein, die genauen User-Agent-Strings, die in Ihren Logs erscheinen, zu überprüfen und die SPLs entsprechend anzupassen.
