Sure, here is the translated and rearranged sequence of the provided text in markdown format:


# WinEventlog Statistics

## 1. Daily Overview

```markdown
index=windows EventCode IN (4800,4801) 
| timechart span=1h count by EventCode
```

## 2. Lunch Break Duration
Assuming your lunch break is between 12:00 and 14:00.

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

## 3. Total Break Time

```spl
index=windows EventCode=4800 
| transaction startswith=EventCode="4800" endswith=EventCode="4801" 
| eval duration=(duration/60) 
| stats sum(duration) as TotalPauseTime by date_mday, date_month
```

## 4. Longest Uninterrupted Work Time

```spl
index=windows EventCode IN (4800,4801) 
| transaction startswith=EventCode="4801" endswith=EventCode="4800" 
| eval duration=(duration/60) 
| stats max(duration) as MaxWorkTime by date_mday, date_month
```

## 5. Break Frequency

```spl
index=windows EventCode=4800 
| stats count by date_mday, date_month
```

## 6. Week-to-Week Comparison

```spl
index=windows EventCode=4800 
| transaction startswith=EventCode="4800" endswith=EventCode="4801" 
| eval duration=(duration/60) 
| stats sum(duration) as TotalPauseTime by date_wday
```

## 7. Time of Day vs. Break Duration

```spl
index=windows EventCode=4800 
| transaction startswith=EventCode="4800" endswith=EventCode="4801" 
| eval duration=(duration/60), hour=strftime(_time, "%H") 
| stats avg(duration) as AvgPauseTime by hour
```

# Bluecoat Logging

BlueCoat, now known as Symantec Proxy, provides detailed web logs containing information about user web traffic. If you have indexed these logs in Splunk, you can create various panels to analyze your Edge browser surfing behavior.

Here are some panel suggestions and corresponding SPLs based on typical fields in BlueCoat logs:

## 1. Top Visited Domains
### Top Visited Domains
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| top limit=10 cs_host
```

## 2. Daily Internet Usage (by Hour)
### Daily Internet Usage
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| timechart span=1h count by cs_host
```

## 3. Categories of Visited Websites
### Categories of Visited Websites
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| top limit=10 cs_categories
```

## 4. Downloaded Traffic Volume
### Downloaded Traffic Volume
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| stats sum(sc_bytes) as TotalDownloaded 
```

## 5. Uploaded Traffic Volume
### Uploaded Traffic Volume
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| stats sum(cs_bytes) as TotalUploaded 
```

## 6. Top File Types Downloaded
### Top File Types Downloaded
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| top limit=10 cs_mime_type
```

## 7. Total Internet Usage Duration
### Total Internet Usage Duration
```spl
index=bluecoat cs_UserAgent="*Edge*" 
| stats sum(duration) as TotalDuration 
```

# Detecting DLL Hijacking with Sysmon Logs in Splunk

**Author:** Ben Folland

## Introduction

DLL hijacking is a technique where an adversary uses a legitimate application to load a malicious DLL with the intention of executing code. This article will guide you on how to detect DLL hijacking using Sysmon logs indexed in Splunk.

## What is DLL Hijacking?

DLL hijacking involves tricking an application into loading a rogue DLL instead of the legitimate one. This can be achieved in several ways:

1. **Search Order DLL Hijacking:** The OS searches for the DLL in a specific order of directories. An attacker can place their rogue DLL in a location higher up in this search order.
2. **Replacing the DLL:** The legitimate DLL is replaced with the rogue one.
3. **Relative Path DLL Hijacking:** The legitimate application is copied to a folder the user has write access to, and the rogue DLL is placed in the same directory.

## Why is it Important?

DLL hijacking can be used for:

- **Persistence:** If the legitimate executable is run frequently, a rogue DLL can provide continuous access.
- **Privilege Escalation:** If the target executable runs with elevated permissions, so will the malicious DLL.
- **Defense Evasion:** Running a trusted executable might not raise suspicions.

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

## Splunk Search Example

To detect DLL hijacking in Splunk, you can use a search query like:

```spl
index=sysmon EventCode=7 Image=*calc.exe* | where NOT Path LIKE "C:\\Windows\\System32%" OR NOT Signature="Microsoft Windows"
```

This search looks for `calc.exe` loading DLLs outside the usual `System32` directory or those not signed by Microsoft.

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

## Conclusion

DLL hijacking is a potent technique for adversaries. Using tools like Sysmon and Splunk, defenders can detect and respond to such threats effectively. Proper configuration and continuous refinement are key to accurate detection.

# Detecting Executions Resulting from Opening a PDF or Clicking Links within a Document in Acrobat Reader

## Introduction

Detecting executions resulting from opening a PDF or clicking links within a document in Acrobat Reader requires monitoring user actions, file system activities, and network connections. This guide will help you set up detection rules in Splunk for such activities.

## Prerequisites

- Ensure that you have logs from endpoints forwarded to Splunk. This includes:
  - Windows Event Logs
  - Sysmon logs (for detailed system activity)
  - Adobe Acrobat Reader logs (if available)

## 1. Detecting PDF Open Events

To detect when a PDF is opened with Acrobat Reader, monitor process execution events related to Acrobat Reader in Splunk. Use a search like:

```spl
index=windows EventCode=4688 ProcessName="AcroRd32.exe" 
```

## 2. Detecting Link Clicks within PDF

Detecting link clicks within a PDF can be more complex. Look for processes spawned by Acrobat Reader, which could be the result of clicking a link within a PDF. Use a search like:

```spl
index=windows EventCode=4688 ParentProcessName="AcroRd32.exe"
```

## 3. Monitoring Network Connections

If a link within the PDF leads to an external website, monitor network connections initiated immediately after the PDF is opened:

```spl
index=sysmon EventCode=3 ParentProcessName="AcroRd32.exe"
```

## 4. Correlating Events

Correlate the time of the PDF being opened with subsequent process executions or network connections to increase accuracy:

```spl
index=windows (EventCode=4688 ProcessName="AcroRd32.exe") OR (EventCode=4688 ParentProcessName="AcroRd32.exe") | transaction startswith=ProcessName="AcroRd32.exe" endswith=ParentProcessName="AcroRd32.exe"
```

## 5. Alerts

Set up alerts in Splunk based on the searches above to be proactively informed about suspicious activities. For example, if a PDF opens a process or makes a network connection to a known malicious IP, trigger an alert.

## 6. Additional Tips

- **Whitelisting:** Define known good processes and network connections to reduce false positives.
  
- **User Behavior:** Monitor unusual user behavior, such as opening PDFs at odd hours or opening a large number of PDFs quickly.
  
- **File Origin:** Consider the origin of the PDF. Files from the internet or email attachments might be riskier than internal files.
  
- **PDF Analysis Tools:** Use specialized tools that analyze PDFs for malicious content and consider integrating them into your security stack.

## Conclusion

Detecting malicious activities resulting from PDF interactions is important for security. Using Splunk and the provided detection methods, you can effectively monitor and respond to such threats. Always use a layered security approach for comprehensive protection.

# Splunk Field Extraction Guide

Splunk offers built-in tools for field extraction that allow users to easily extract fields from data without needing to write complex regex patterns. This guide will walk you through the basics of field extraction in Splunk and provide examples of how to use these tools effectively.

## Table of Contents
1. Introduction to Field Extraction in Splunk
2. Basics of Splunk Field Extraction
3. Using Splunk Field Extractor
   - Interactive Field Extractor (IFX)
   - Delimiter-Based Extraction
   - Regular Expression-Based Extraction
4. Tips and Tricks
5. Conclusion

## 1. Introduction to Field Extraction in Splunk
Splunk's Field Extraction tools provide an intuitive way to extract meaningful fields from logs and events, enriching your data and making it easier to analyze.

## 2. Basics of Splunk Field Extraction

- **Search-time vs. Index-time**: Splunk allows field extraction at both search-time (when you run a search) and index-time (when data is ingested). This guide will focus on search-time extraction.
- **Field Extractor**: A built-in Splunk tool that assists in creating field extractions.

## 3. Using Splunk Field Extractor

### Interactive Field Extractor (IFX)

1. **Start with a Search**: Begin with a search that returns the types of events you want to extract fields from.
2. **Select an Event**: Click on an event and choose "Extract Fields" from the dropdown.
3. **Highlight Data**: Highlight the portion of the event you want to extract and Splunk will suggest a field name and show how it extracts that field from other events.
4. **Refine and Save**: You can adjust the extraction if necessary and then save it.

### Delimiter-Based Extraction

If your data has clear delimiters, you can use them to extract fields.

1. **Use the `rex` Command**: 
   ```
   | rex field=_raw "key1=(?<field1>value1) key2=(?<field2>value2)"
   ```
2. **Define Field Names**: Within the `<>`, specify the field name you want to use for the extracted value.

### Regular Expression-Based Extraction

For more complex data, you might need to use regex for extraction.

1. **Use the `rex` Command with Regex**: 
   ```
   | rex field=_raw "(?i)user=(?<username>\w+)"
   ```
2. **Specify Field and Pattern**: The `field` argument specifies which field to extract from. The regex pattern follows the same principles as in the earlier regex guide.

## 4. Tips and Tricks

- **Test Extractions**: Always test your field extractions on a variety of events to ensure they work as expected.
- **Use Splunk's Field Transformations**: Field transformations allow you to derive new fields from existing ones.
- **Leverage Splunk's Field Discovery**: Splunk can automatically discover and suggest fields for extraction based on your data.

## 5. Conclusion

Splunk's Field Extraction tools simplify the process of deriving meaningful fields from your data. By understanding and leveraging these tools, you can enhance your data analysis capabilities in Splunk.

---

Remember, while Splunk provides intuitive tools for field extraction, having a basic understanding of regex can further improve your extraction capabilities, especially for complex datasets.

# Splunk Regex Guide

Regular Expressions (regex) are a powerful way to parse fields from logs and messages in Splunk. This guide provides a primer on Splunk regex, including basic concepts and examples for extracting various types of data.

## Table of Contents
1. Introduction to Regex in Splunk
2. Basics of Splunk Regex
3. Examples
   - Extracting IP Addresses
   - Extracting Usernames
   - Extracting Hashes


   - And More...
4. Tips and Tricks
5. Conclusion

## 1. Introduction to Regex in Splunk
Splunk uses regex to search, filter, and extract fields in data. Familiarity with regex syntax and its application will be beneficial in harnessing Splunk's full capabilities.

## 2. Basics of Splunk Regex

- **Matching Characters**: Use regular characters to match themselves.
- **Wildcards**: `.` matches any single character.
- **Quantifiers**: `*` (0 or more), `+` (1 or more), `?` (0 or 1), `{n}` (exactly n times).
- **Character Classes**: `[...]` matches any one character inside the brackets.
- **Escape Sequences**: Use `\` to escape special characters.

## 3. Examples

### Extracting IP Addresses

To extract IPv4 addresses:
```
(?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
```
- `?<ip>` names the extraction as "ip".
- `\d{1,3}` matches 1 to 3 digits.

### Extracting Usernames

To extract a username in the format "user:username":
```
user:(?<username>\w+)
```
- `?<username>` names the extraction as "username".
- `\w` matches any word character (equivalent to `[a-zA-Z0-9_]`).

### Extracting Hashes

For MD5 (32 hex characters):
```
(?<md5hash>[a-fA-F0-9]{32})
```

For SHA-256 (64 hex characters):
```
(?<sha256hash>[a-fA-F0-9]{64})
```

### Extracting Email Addresses

To extract an email address:
```
(?<email>[\w\.-]+@[\w\.-]+\.\w+)
```

### Extracting URLs

To extract a URL:
```
(?<url>https?://\S+)
```
- `https?` matches "http" or "https".
- `\S` matches any non-whitespace character.

## 4. Tips and Tricks

- **Non-Capturing Groups**: Use `(?:...)` to group patterns without capturing the matched content.
- **Lookaheads and Lookbehinds**: Use `(?=...)` for positive lookaheads and `(?<=...)` for positive lookbehinds.
- **Case Sensitivity**: Splunk's regex is case-sensitive by default. Use `(?i)` at the start to make the pattern case-insensitive.

# Splunk Field Extraction Guide

Splunk offers built-in tools for field extraction that allow users to easily extract fields from data without needing to write complex regex patterns. This guide will walk you through the basics of field extraction in Splunk and provide examples of how to use these tools effectively.

## Table of Contents
1. Introduction to Field Extraction in Splunk
2. Basics of Splunk Field Extraction
3. Using Splunk Field Extractor
   - Interactive Field Extractor (IFX)
   - Delimiter-Based Extraction
   - Regular Expression-Based Extraction
4. Tips and Tricks
5. Conclusion

## 1. Introduction to Field Extraction in Splunk
Splunk's Field Extraction tools provide an intuitive way to extract meaningful fields from logs and events, enriching your data and making it easier to analyze.

## 2. Basics of Splunk Field Extraction

- **Search-time vs. Index-time**: Splunk allows field extraction at both search-time (when you run a search) and index-time (when data is ingested). This guide will focus on search-time extraction.
- **Field Extractor**: A built-in Splunk tool that assists in creating field extractions.

## 3. Using Splunk Field Extractor

### Interactive Field Extractor (IFX)

1. **Start with a Search**: Begin with a search that returns the types of events you want to extract fields from.
2. **Select an Event**: Click on an event and choose "Extract Fields" from the dropdown.
3. **Highlight Data**: Highlight the portion of the event you want to extract and Splunk will suggest a field name and show how it extracts that field from other events.
4. **Refine and Save**: You can adjust the extraction if necessary and then save it.

### Delimiter-Based Extraction

If your data has clear delimiters, you can use them to extract fields.

1. **Use the `rex` Command**: 
   ```
   | rex field=_raw "key1=(?<field1>value1) key2=(?<field2>value2)"
   ```
2. **Define Field Names**: Within the `<>`, specify the field name you want to use for the extracted value.

### Regular Expression-Based Extraction

For more complex data, you might need to use regex for extraction.

1. **Use the `rex` Command with Regex**: 
   ```
   | rex field=_raw "(?i)user=(?<username>\w+)"
   ```
2. **Specify Field and Pattern**: The `field` argument specifies which field to extract from. The regex pattern follows the same principles as in the earlier regex guide.

## 4. Tips and Tricks

- **Test Extractions**: Always test your field extractions on a variety of events to ensure they work as expected.
- **Use Splunk's Field Transformations**: Field transformations allow you to derive new fields from existing ones.
- **Leverage Splunk's Field Discovery**: Splunk can automatically discover and suggest fields for extraction based on your data.

## 5. Conclusion

Splunk's Field Extraction tools simplify the process of deriving meaningful fields from your data. By understanding and leveraging these tools, you can enhance your data analysis capabilities in Splunk.

---

# Splunk Regex Guide

Regular Expressions (regex) are a powerful way to parse fields from logs and messages in Splunk. This guide provides a primer on Splunk regex, including basic concepts and examples for extracting various types of data.

## Table of Contents
1. Introduction to Regex in Splunk
2. Basics of Splunk Regex
3. Examples
   - Extracting IP Addresses
   - Extracting Usernames
   - Extracting Hashes
   - And More...
4. Tips and Tricks
5. Conclusion

## 1. Introduction to Regex in Splunk
Splunk uses regex to search, filter, and extract fields in data. Familiarity with regex syntax and its application will be beneficial in harnessing Splunk's full capabilities.

## 2. Basics of Splunk Regex

- **Matching Characters**: Use regular characters to match themselves.
- **Wildcards**: `.` matches any single character.
- **Quantifiers**: `*` (0 or more), `+` (1 or more), `?` (0 or 1), `{n}` (exactly n times).
- **Character Classes**: `[...]` matches any one character inside the brackets.
- **Escape Sequences**: Use `\` to escape special characters.

## 3. Examples

### Extracting IP Addresses

To extract IPv4 addresses:
```
(?<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
```
- `?<ip>` names the extraction as "ip".
- `\d{1,3}` matches 1 to 3 digits.

### Extracting Usernames

To extract a username in the format "user:username":
```
user:(?<username>\w+)
```
- `?<username>` names the extraction as "username".
- `\w` matches any word character (equivalent to `[a-zA-Z0-9_]`).

### Extracting Hashes

For MD5 (32 hex characters):
```
(?<md5hash>[a-fA-F0-9]{32})
```

For SHA-256 (64 hex characters):
```
(?<sha256hash>[a-fA-F0-9]{64})
```

### Extracting Email Addresses

To extract an email address:
```
(?<email>[\w\.-]+@[\w\.-]+\.\w+)
```

### Extracting URLs

To extract a URL:
```
(?<url>https?://\S+)
```
- `https?` matches "http" or "https".
- `\S` matches any non-whitespace character.

## 4. Tips and Tricks

- **Non-Capturing Groups**: Use `(?:...)` to group patterns without capturing the matched content.
- **Lookaheads and Lookbehinds**: Use `(?=...)` for positive lookaheads and `(?<=...)` for positive lookbehinds.
- **Case Sensitivity**: Splunk's regex is case-sensitive by default. Use `(?i)` at the start to make the pattern case-insensitive.

## 5. Conclusion

Splunk regex is a powerful tool for parsing and extracting meaningful data from logs. This guide provides a starting point, but practice and experimentation are key to mastery.

---
