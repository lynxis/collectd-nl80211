#!/bin/bash
cat build_system.patch > 999-nl80211.patch
cat >> 999-nl80211.patch  <<EOF
diff --git a/src/collectd-nl80211.c b/src/collectd-nl80211.c
new file mode 100644
index 0000000..366124a
EOF
diff -u /dev/null  collectd-nl80211.c   | tail -n+3 >> 999-nl80211.patch
