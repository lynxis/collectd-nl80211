cmake_minimum_required(VERSION 2.6)

PROJECT(colnl C)

ADD_DEFINITIONS(-Wall --std=gnu99 -g -Wno-unused-variable)
include_directories("/home/lynxis/projects/collectd/src/")
include_directories("/usr/include/libnl3/")

add_library(collectd-nl80211 MODULE collectd-nl80211.c)
target_link_libraries(collectd-nl80211 nl-genl-3 nl-3)
