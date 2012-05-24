cmake_minimum_required(VERSION 2.6)

PROJECT(colnl C)

ADD_DEFINITIONS(-Os -Wall --std=gnu99 -g3)
include_directories("/usr/include/libnl3/")

add_executable(collectd-nl80211 collectd-nl80211.c)
target_link_libraries(collectd-nl80211 nl-genl-3 nl-3)
