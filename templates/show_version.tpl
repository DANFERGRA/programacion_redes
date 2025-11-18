# Cisco IOS - show version
# Extrae hostname, version y uptime
Value Required Hostname (\S+)
Value Required Version (\S+)
Value Required Uptime (.+)

Start
  ^${Hostname}\s+uptime\s+is\s+${Uptime}\s*$ -> UPTIME
  ^.*\sVersion\s+${Version},.* -> Continue
  ^.* -> Continue

UPTIME
  ^.* -> Record
