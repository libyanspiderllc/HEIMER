## ~~1.1.0_1~~ (RESOLVED)

Clicking `w` returns this error when Auto-Refresh is enabled:

```
╭─────────────────────────────────────────────────────────────── Traceback (most recent call last) ────────────────────────────────────────────────────────────────╮
│ in _auto_refresh_tick:1433                                                                                                                                       │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
NoMatches: No nodes match <class '__main__.ConnectionTable'> on NetworkApp(title='HEIMER - LS Web Attack Response Tool', classes={'-dark-mode'},
pseudo_classes={'focus', 'dark'})
```

## ~~1.1.0_2~~ (RESOLVED)

When Whois information contain special characters, the app crashes. This happens when accessing Whois for 185.177.72.29. It has special characters in some whois fields, such as: address:        10 Allée Latécoère

## 1.1.0_2

When Whois information contain special characters, the app crashes. This happens when accessing Whois for 185.177.72.29. It has special characters in some whois fields, such as: address:        10 Allée Latécoère

