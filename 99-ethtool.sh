#!/bin/bash
# BEGIN 99-ethtool.sh
# /etc/NetworkManager/dispatcher.d/99-ethtool.sh
# chmod +x /etc/NetworkManager/dispatcher.d/99-ethtool.sh
if [[ $2 == up ]]; then
	SCRIPT="$(basename "$0")"
	if [[ -e $CONNECTION_FILENAME ]]; then
		source $CONNECTION_FILENAME
		if [[ -n $ETHTOOL_CMD ]]; then
		ETHTOOL_CMD="/usr/sbin/ethtool $ETHTOOL_CMD"
			if $ETHTOOL_CMD; then
				logger "$SCRIPT: success: $ETHTOOL_CMD"
			else
				logger "$SCRIPT: failed: $ETHTOOL_CMD"
			fi
		else
		logger "$SCRIPT: ETHTOOL_CMD not in $CONNECTION_FILENAME, skipping"
		fi
	else
	logger "$SCRIPT: $CONNECTION_FILENAME does not exist?"
	fi
fi