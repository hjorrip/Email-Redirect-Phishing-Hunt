# Email-Redirect-Phishing-Hunt

```
let my_domain = @"@example.com"; // update this line
EmailUrlInfo 
| where Url contains @"=http" and Url endswith my_domain  
| extend RedirectToUrl = extract(@"(=http.+)",1, Url)
| extend RedirectToUrl = substring(RedirectToUrl, 1)
| extend RedirectToUrl = url_decode(RedirectToUrl)
| extend RedirectToDomain = extract(@"(http.+\/\/.+?)(\/)", 1, RedirectToUrl)
| extend TargetedAccount = tostring(split(RedirectToUrl, "/")[-1])
| extend TargetedAccount = extract(@"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", 0, TargetedAccount)
| extend RedirectFromDomain = UrlDomain
| join kind=leftouter EmailEvents on $left.NetworkMessageId == $right.NetworkMessageId
| summarize arg_max(Timestamp, *) by NetworkMessageId
| summarize FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp),
            CountOfRedirectToDomain = dcount(tostring(RedirectToDomain)), 
            NumberOfEmails = dcount(NetworkMessageId),
            CountOfTargetAccounts = dcount(tostring(TargetedAccount)), 
            OriginalUrlList = make_set(Url), 
            RedirectToUrlList = make_set(RedirectToUrl), 
            RedirectToDomainList =  make_set(RedirectToDomain), 
            TargetAccountList = make_set(TargetedAccount),
            Delivered = countif(LatestDeliveryAction == "Delivered"),
            Blocked = countif(LatestDeliveryAction == "Blocked"),
            Qurantined = countif(LatestDeliveryAction contains "quarantine"),
            Deleted = countif(LatestDeliveryAction contains "delete"),
            Junked = countif(LatestDeliveryAction contains "junked"),
            Other = countif(LatestDeliveryAction !contains "quarantine" and LatestDeliveryAction !contains "delete" and LatestDeliveryAction !contains "junked" and LatestDeliveryAction != "Blocked")
                by RedirectFromDomain
| order by CountOfRedirectToDomain, CountOfTargetAccounts
| project-reorder FirstSeen, LastSeen, RedirectFromDomain, NumberOfEmails, CountOfRedirectToDomain, CountOfTargetAccounts
```



