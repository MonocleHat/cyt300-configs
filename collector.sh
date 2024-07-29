#!/bin/bash
cp /etc/filebeat/filebeat.yml ./filebeat.yml
cp /etc/filebeat/wazuh-template.json ./wazuh-template.json
cp /var/ossec/etc/ossec.conf ./ossec.conf
cp /etc/wazuh-indexer/opensearch.yml ./opensearch.yml
cp /etc/wazuh-dashboard/opensearch_dashboards.yml ./opensearch_dashboards.yml
cp /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml ./wazuh.yml
cp /var/ossec/etc/decoders/local_decoder.xml ./local_decoder.xml
cp /var/ossec/etc/rules/local_rules.xml ./local_rules.xml
echo "Script done"
