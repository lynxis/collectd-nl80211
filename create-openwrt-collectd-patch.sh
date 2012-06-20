#!/bin/bash
cat build_system.patch > 999-nl80211.patch
diff -urp /dev/null collectd-nl80211.c >> 999-nl80211.patch
