#!/bin/sh
cat build_system.patch > 999-nl80211.patch
cat >> 999-nl80211.patch  <<EOF
diff --git a/src/collectd-nl80211.c b/src/collectd-nl80211.c
new file mode 100644
index 0000000..366124a
--- a/src/collectd-nl80211.c
+++ b/src/collectd-nl80211.c
EOF
diff -u /dev/null  collectd-nl80211.c   | tail -n+3 >> 999-nl80211.patch
sed -i 's!<linux/nl80211.h!<mac80211/linux/nl80211.h!' 999-nl80211.patch
