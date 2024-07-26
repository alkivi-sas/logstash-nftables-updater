# logstash-nftables-updater

Simple script that we internally use to update :

 - NFTable with all necessary IPs (insert and remove)
 - Logstash configuration file to identify, based on IP, where the traffic comes from
 - Reload logstash to apply changes

## Usage
Python 3.11 and pipenv
```
git clone
pipenv install
...
````
## Related project
https://github.com/alkivi-sas/logstash-pfsense
