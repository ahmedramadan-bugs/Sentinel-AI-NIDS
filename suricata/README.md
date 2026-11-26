# Suricata integration

The NIDS reads Suricata's EVE JSON file; it does not capture packets or run
Suricata itself. Configure the monitored Suricata instance to write at least
`flow` and `alert` records to the `NIDS_EVE_LOG` path. The default development
path is `runtime/eve.json` in this repository.

To load the optional local rules, copy `nids-local.rules` to the directory
referenced by Suricata's `default-rule-path`, add it to `rule-files` in the
same YAML configuration, and validate the complete configuration before any
live capture:

```text
suricata -T -c /etc/suricata/suricata.yaml
```

No Suricata executable or deployment YAML was included in this repository, so
the validation command could not be executed as part of this repair. The
Python fallback engine still maps all Suricata alert signatures from EVE JSON
and remains active if ML is unavailable.

## Rules files

`suricata/nids-local.rules` is the **single source of truth** for custom
detection rules.  `suricata_system_config/local.rules` is an identical copy
kept alongside the system YAML for reference; keep them in sync manually or
use `cp suricata/nids-local.rules suricata_system_config/local.rules` after
every edit.

To deploy to the live system:
```bash
sudo cp suricata/nids-local.rules /etc/suricata/rules/nids-local.rules
sudo systemctl restart suricata
```
