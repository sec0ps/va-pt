#!/bin/sh
# 
# OpenVAS
# $Id$
# Description: Synchronize with NVT feed.
# This shell script synchronizes the local set of
# OpenVAS Network Vulerability Tests (NVTs) and
# associated includefiles with a given upstream
# feed of updated or new files.
#
# Authors:
# Vlatko Kosturjak <k...@linux.hr>
# 
# Script is complete rewrite of original sync script by 
# Lukas Grunwald <l.grunw...@dn-systems.de>
# Jan-Oliver Wagner <jan-oliver.wag...@intevation.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.


# these locations should be correct if standard ./configure had
# been applied.

prefix=/usr
exec_prefix=${prefix}
sysconfdir=/etc
libdir=/var/lib
localstatedir=/var/run

# configure NVT_DIR where we will sync NVTs
if [ -z "$NVT_DIR" ]; then
        NVT_DIR="/var/lib/openvas/plugins"
fi

# The URL of the plugin feed
if [ -z "$OVRSYNCFEED" ]; then
        OVRSYNCFEED=rsync://rsync.openvas.org:/nvt-feed
        # An alternative syntax which might work if the above doesn't:
        # ovrsyncfeed=rs...@rsync.openvas.org::nvt-feed
fi

if [ -z "$OVHTTPFEED" ]; then
        OVHTTPFEED=http://www.openvas.org/openvas-nvt-feed-current.tar.bz2
fi

if [ -z "$TMPDIR" ]; then
        SYNCTMPDIR=/tmp
else
        SYNCTMPDIR="$TMPDIR"
fi
        
echo "OpenVAS NVT Sync $Release$"
echo " "

if [ "$1" = "--help" ]; then
        echo "$0: Sync NVTs using different protocols"
        echo "--rsync           sync with rsync (default)"
        echo "--wget            sync with wget"
        echo "--curl            sync with curl"
        echo "--check           just checksum check"
        echo ""
        echo "Enviroment variables:"
        echo "NVT_DIR           where to extract plugins"
        echo "OVRSYNCFEED       URL of rsync feed" 
        echo "OVHTTPFEED        URL of http feed"
        echo "Note that you can use standard ones as well (e.g. http_proxy) for 
wget/curl"
        echo ""
        exit 0
fi

echo "[i] NVT dir: $NVT_DIR"

CMDRSYNC=`which rsync`
CMDMD5SUM=`which md5sum`
CMDWGET=`which wget`
CMDCURL=`which curl`
CMDMETHOD=""

if [ "$1" = "--rsync" ]; then
        CMDMETHOD="rsync"
fi
if [ "$1" = "--wget" ]; then
        CMDMETHOD="wget"
fi
if [ "$1" = "--curl" ]; then
        CMDMETHOD="curl"
fi
if [ "$1" = "--check" ]; then
        CMDMETHOD="check"
fi

if [ -z "$1" ]; then
        if [ -z "$CMDRSYNC" ]; then 
                echo "[w] rsync not found!"
                if [ -z "$CMDWGET"]; then
                        echo "[w] GNU wget not found!"
                        if [ -z "$CMDCURL"]; then
                                echo "[w] curl not found!"
                                echo -n "[e] no utility available in PATH 
enviroment variable to download plugins"      
                                exit 1
                        else
                                echo "[i] Will use curl"
                                CMDMETHOD="curl"
                        fi
                else
                        echo "[i] Will use wget"
                        CMDMETHOD="wget"
                fi
        else 
                echo "[i] Will use rsync"
                CMDMETHOD="rsync"
        fi
fi

if [ "$CMDMETHOD" = "rsync" ]; then
        if [ -z "$CMDRSYNC" ]; then 
                echo "[e] rsync not found!"
                exit 1
        else 
                echo "[i] Using rsync: $CMDRSYNC"
                echo "[i] Configured NVT rsync feed: $OVRSYNCFEED"
                mkdir -p "$NVT_DIR"
                eval "$CMDRSYNC -ltvrP \"$OVRSYNCFEED\" \"$NVT_DIR\""
                if [ $? -ne 0 ] ; then
                        echo "Error: rsync failed. Your NVT collection might be 
broken now."
                        exit 1
                fi
        fi
fi

TMPNVT="$SYNCTMPDIR/openvas-feed-`date +%F`-$$.tar.bz2"

if [ "$CMDMETHOD" = "wget" ]; then
        if [ -z "$CMDWGET" ]; then 
                echo "[e] GNU wget not found!"
                exit 1
        else 
                echo "[i] Using GNU wget: $CMDWGET"
                echo "[i] Configured NVT http feed: $OVHTTPFEED"
                echo "[i] Downloading to: $TMPNVT"
                mkdir -p "$NVT_DIR" \
                && wget "$OVHTTPFEED" -O $TMPNVT \
                && cd "$NVT_DIR" \
                && tar xvjf $TMPNVT \
                && rm -f $TMPVNT \
                && echo "[i] Download complete"
        fi
fi

if [ "$CMDMETHOD" = "curl" ]; then
        if [ -z "$CMDCURL" ]; then 
                echo "[e] curl not found!"
                exit 1
        else 
                echo "[i] Using curl: $CMDCURL"
                echo "[i] Configured NVT http feed: $OVHTTPFEED"
                echo "[i] Downloading to: $TMPNVT"
                mkdir -p "$NVT_DIR" \
                && curl "$OVHTTPFEED" -o $TMPNVT \
                && cd "$NVT_DIR" \
                && tar xvjf $TMPNVT \
                && rm -f $TMPVNT \
                && echo "[i] Download complete"
        fi
fi

if [ -z "CMDMD5SUM" ]; then
        echo "[w] md5sum utility not found, cannot check NVT checksums! You've 
been warned!"
else
        echo -n "[i] Checking dir: "    
        eval "cd \"$NVT_DIR\""
        if [ $? -ne 0 ] ; then
                echo "not ok"
                echo "Check your NVT dir for existance and permissions!"
                exit 1
        else
                echo "ok"
        fi
        echo -n "[i] Checking MD5 checksum: "   
        eval "cd \"$NVT_DIR\" ; $CMDMD5SUM -c --status \"$NVT_DIR/md5sums\""
        if [ $? -ne 0 ] ; then
                echo "not ok"
                echo "Error: md5sums not correct. Your NVT collection might be 
broken now."
                echo "Please try this for details: cd \"$NVT_DIR\" ; $CMDMD5SUM 
-c \"$NVT_DIR/md5sums\" | less"
                exit 1
        fi      
        echo "ok"
fi

