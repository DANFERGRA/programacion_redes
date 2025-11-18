# Cisco IOS - show ip interface brief
Value Required Interface (\S+)
Value IP (\S+|unassigned)
Value OK\? (\S+)
Value Method (\S+)
Value Status (administratively down|up|down)
Value Protocol (up|down)

Start
  ^Interface\s+IP-Address\s+OK\?.* -> Continue
  ^${Interface}\s+${IP}\s+${OK\?}\s+${Method}\s+${Status}\s+${Protocol}\s*$ -> Record
  ^.* -> Continue
