# graylog-ban

Like fail2ban, graylog-ban generates drop rules out of graylog-sources. Other than syslog-files, graylog-sources offers much more control and convenience regarding data-selection.

## usage
```
graylog-ban.py <graylog-api-host> <api-token> <query-source-location> <whitelist-file> <firewall-chain> <firewall-action>
```

1. JSON files in the <query-source-location> will be loaded and queried against the graylog server. All IPs will be loaded from the results. IPs occurring multiple times will only counted once's.
1. the firewall chain <firewall-chain> will be queried and all rules are examined. Rules that affects IPs not appeared in the graylog-queries will be dropped.
1. All IPs listed by the graylog-queries that doesn't appear in the Firewall chain will be created. <firewall-action> will be used as target.
  
Currently iptables is implemented as firewall back-end. The rules will be setup-ed like this:
```
iptables -I <firewall-chain> 1 -d <ip-from-graylog> -m comment --comment "sources where the ip appears..." -j <firewall-action>
```
  
## ban and unban
Other than in fail2ban, the whole timing part is done via the queries itself. As long as a IP appears in the queries, it will be blocked via firewall. The time-range is defined in the queries.
  
## example setup
### firewall rules
Creates two chains. DROPLOG is just a helper to log and drop packages. All packages from wan0 will be routed through the chain dynamic-blocker.
```
$iptables -N dynamic-blocker
$iptables -A dynamic-blocker -j RETURN

$iptables -N DROPLOG 
$iptables -A DROPLOG -j LOG --log-prefix='[dynamic-blocker] '
$iptables -A DROPLOG -j DROP

$iptables -A INPUT -i wan0 -j dynamic-blocker

```
### graylog
The log output of iptables must be handled by graylog, as well as other input for "suspicious" traffic.

In this case there are two sources. On for the dynamic-blocker to keep IPs in the Firewall who are actively used while being blocked and a second to extract IPs from postfix.

graylog-queries/dynamic-blocker.json
```
{
    "id": "dynamic-blocker",
    "timerange": {
        "type": "keyword",
        "keyword": "last 2 days"
    },
    "query": {
        "type": "elasticsearch",
        "query_string": "chain:dynamic-blocker"
    },
    "search_types": [
        {
            "id": "dynamic-blocker",
            "name": "dynamic-blocker",
            "rollup": false,
            "row_groups": [{
                "field": "remote-ip",
                "limit": 250,
                "type": "values"
            }],
            "series": [],
            "sort": [],
            "streams": [],
            "type": "pivot"
        }
    ],
    "filter": {
        "type": "or",
        "filters": [
            {
                "type": "stream",
                "title": "firewall"
            }
        ]
    }
}
```
graylog-queries/postfix.json
```
{
    "id": "postfix",
    "timerange": {
        "type": "keyword",
        "keyword": "last 2 days"
    },
    "query": {
        "type": "elasticsearch",
        "query_string": "hostname:unknown"
    },
    "search_types": [
        {
            "id": "postfix",
            "name": "postfix",
            "rollup": false,
            "row_groups": [{
                "field": "remote-ip",
                "limit": 250,
                "type": "values"
            }],
            "series": [],
            "sort": [],
            "streams": [],
            "type": "pivot"
        }
    ],
    "filter": {
        "type": "or",
        "filters": [
            {
                "type": "stream",
                "title": "postfix"
            }
        ]
    }
}
```
### cron-rule
```
*/15    *       * * *     root /<path>/graylog-ban.py <graylogserver> <api-key> graylog-queries whitelist  dynamic-blocker DROPLOG
```
