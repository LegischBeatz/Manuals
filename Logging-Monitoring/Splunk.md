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

# Detecting DLL Hijacking with Sysmon Logs in Splunk

**Author:** Ben Folland

---

## Introduction

DLL hijacking is a technique where an adversary uses a legitimate application to load a malicious DLL with the intention of executing code. This article will guide you on how to detect DLL hijacking using Sysmon logs indexed in Splunk.

---

## What is DLL Hijacking?

DLL hijacking involves tricking an application into loading a rogue DLL instead of the legitimate one. This can be achieved in several ways:

1. **Search Order DLL Hijacking:** The OS searches for the DLL in a specific order of directories. An attacker can place their rogue DLL in a location higher up in this search order.
2. **Replacing the DLL:** The legitimate DLL is replaced with the rogue one.
3. **Relative Path DLL Hijacking:** The legitimate application is copied to a folder the user has write access to, and the rogue DLL is placed in the same directory.

---

## Why is it Important?

DLL hijacking can be used for:

- **Persistence:** If the legitimate executable is run frequently, a rogue DLL can provide continuous access.
- **Privilege Escalation:** If the target executable runs with elevated permissions, so will the malicious DLL.
- **Defense Evasion:** Running a trusted executable might not raise suspicions.

---

## Detection with Sysmon

Sysmon provides granular logging on various events, including DLL image loads. By default, it outputs logs in `.evtx` format. For effective detection:

1. **Install Sysmon:** Download the executable [here](https://link_to_sysmon).
2. **Configure Sysmon:** Use a configuration file like the one provided by SwiftOnSecurity. Ensure DLL image loads are logged.

```xml
<RuleGroup name="" groupRelation="or">
  <ImageLoad onmatch="exclude">
  </ImageLoad>
</RuleGroup>
```

3. **Index Sysmon Logs in Splunk:** Ensure that the Sysmon logs are being forwarded and indexed in Splunk.
4. **Search for Suspicious Activity:** In Splunk, search for Event ID 7 (ImageLoad) related to DLLs. Look for:

   - Unsigned DLLs.
   - DLLs loaded from unusual paths.
   - Different hash values for the same DLL name.

---

## Splunk Search Example

To detect DLL hijacking in Splunk, you can use a search query like:

```spl
index=sysmon EventCode=7 Image=*calc.exe* | where NOT Path LIKE "C:\\Windows\\System32%" OR NOT Signature="Microsoft Windows"
```

This search looks for `calc.exe` loading DLLs outside the usual `System32` directory or those not signed by Microsoft.

---

## Refining Detection

To reduce false positives:

1. **Refine Sysmon Config:** Exclude known good paths and applications.

```xml
<ImageLoad onmatch="exclude">
    <Image condition="begin with">C:\Windows\System32\</Image>
    <Image condition="begin with">C:\ProgramData\</Image>
    <Image condition="image">chrome.exe</Image>
    ...
</ImageLoad>
```

2. **Use Sigma Rules:** In complex scenarios, use tools like Chainsaw with Sigma rules to parse Sysmon logs efficiently.

---

## Conclusion

DLL hijacking is a potent technique for adversaries. Using tools like Sysmon and Splunk, defenders can detect and respond to such threats effectively. Proper configuration and continuous refinement are key to accurate detection.



Detecting executions resulting from opening a PDF or clicking links within a document in Acrobat Reader requires a combination of monitoring user actions, file system activities, and network connections. Here's a step-by-step guide to detect such activities using Splunk:

## 1. Prerequisites:

- Ensure that you have logs from the endpoints forwarded to Splunk. This includes:
  - Windows Event Logs
  - Sysmon logs (for detailed system activity)
  - Adobe Acrobat Reader logs (if available)

## 2. Detecting PDF Open Events:

To detect when a PDF is opened with Acrobat Reader, you can look for process execution events related to Acrobat Reader. In Splunk, you might use a search like:

```spl
index=win_event_log EventCode=4688 ProcessName="AcroRd32.exe" 
```

## 3. Detecting Link Clicks within PDF:

Detecting link clicks within a PDF is more challenging. However, if the link in the PDF leads to the opening of a new process (like a web browser), you can detect that subsequent process execution. For example:

```spl
index=win_event_log EventCode=4688 ParentProcessName="AcroRd32.exe"
```

This search will show processes that were spawned by Acrobat Reader, which could be the result of clicking a link within a PDF.

## 4. Monitoring Network Connections:

If the link within the PDF leads to an external website, you can monitor network connections made immediately after the PDF is opened:

```spl
index=sysmon EventCode=3 ParentProcessName="AcroRd32.exe"
```

This will show network connections initiated by Acrobat Reader.

## 5. Correlation:

To increase accuracy, correlate the time of the PDF being opened with subsequent process executions or network connections:

```spl
index=win_event_log (EventCode=4688 ProcessName="AcroRd32.exe") OR (EventCode=4688 ParentProcessName="AcroRd32.exe") | transaction startswith=ProcessName="AcroRd32.exe" endswith=ParentProcessName="AcroRd32.exe"
```

## 6. Alerts:

To be proactively informed about suspicious activities, set up alerts in Splunk based on the searches above. For instance, if a PDF opens a process or makes a network connection to a known malicious IP, you can get an alert.

## 7. Additional Tips:

- **Whitelisting:** There will be many benign processes and network connections initiated by Acrobat Reader. It's essential to whitelist known good behaviors to reduce false positives.
  
- **User Behavior:** Monitor for unusual user behavior, such as opening PDFs at odd hours or opening a large number of PDFs in a short time.

- **File Origin:** Consider the origin of the PDF. Files downloaded from the internet or received as email attachments might be riskier than those created internally.

- **PDF Analysis Tools:** There are specialized tools and platforms that can analyze PDFs for malicious content. Consider integrating such tools into your security stack.

Remember, while these methods can help detect malicious activities resulting from PDF interactions, no single method is foolproof. It's always best to use a layered security approach, combining multiple detection and prevention methods.


# Detecting Home Directory Permission Changes in Linux Using Splunk

**Author:** ChatGPT

---

## Introduction

Changing permissions of home directories in Linux can be a sign of malicious activity, especially if it's done to facilitate unauthorized data transfers. Monitoring and alerting on such changes can help in early detection of potential security incidents. This guide will walk you through detecting these changes using Splunk.

---

## Prerequisites:

- Ensure that you have logs from Linux systems forwarded to Splunk. This includes:
  - Auditd logs (for detailed system activity)
  - Syslog

---

## 1. Monitoring `chmod` and `chown` Commands:

The `chmod` and `chown` commands are used to change file permissions and ownership, respectively. Monitoring the usage of these commands on home directories can provide insights into suspicious activities.

### Splunk Search:

```spl
index=linux_logs (command=chmod OR command=chown) AND (path="/home/*" OR path="~/")
```

---

## 2. Monitoring Specific Permission Changes:

If you're specifically concerned about permissions being opened up (e.g., making a directory world-writable), you can narrow down your search.

### Splunk Search:

```spl
index=linux_logs command=chmod path="/home/*" (mode="777" OR mode="a+w")
```

---

## 3. Correlating with Data Transfer Activities:

If you want to correlate permission changes with potential data transfer activities, you can look for commands like `scp`, `rsync`, or `sftp` executed shortly after the permission change.

### Splunk Search:

```spl
index=linux_logs (command=chmod OR command=chown OR command=scp OR command=rsync OR command=sftp) AND path="/home/*" | transaction user, host startswith=command=chmod endswith=(command=scp OR command=rsync OR command=sftp)
```

---

## 4. Alerts:

To be proactively informed about suspicious activities, set up alerts in Splunk based on the searches above. For instance, if a user changes permissions and then immediately uses `scp`, it could be a sign of data exfiltration.

---

## 5. Additional Tips:

- **User Behavior:** Monitor for unusual user behavior, such as changing permissions at odd hours or by users who typically don't perform such actions.
  
- **Baseline:** Establish a baseline of typical permission changes in your environment. This will help in reducing false positives and focusing on truly suspicious activities.

- **File Integrity Monitoring:** Consider using File Integrity Monitoring (FIM) solutions that can provide more granular insights into file and directory changes.

- **Context:** Always analyze alerts in context. For example, a developer might change permissions temporarily for debugging and then revert them. Such actions, while not best practice, might not be malicious.

---

## Conclusion:

Monitoring home directory permission changes in Linux is crucial for detecting potential data breaches or unauthorized activities. Using Splunk, you can effectively keep an eye on these changes and take swift action when something looks amiss. Always ensure that your logging mechanisms are robust and that you periodically review and refine your alerting criteria.
