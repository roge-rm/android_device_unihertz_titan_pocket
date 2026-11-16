#!/system/bin/sh
# SPDX-License-Identifier: Apache-2.0
# OCV run logger for tools/make-pocket-oz8806-ocv.py. init.pocket.battlog.rc starts it on
# persist.vendor.pocket.battlog=1. It waits for the charger to be unplugged at full, rests,
# then runs about 20 load steps of 5 % each with a rest after each, down to 3500 mV under
# load. Every 10 s it writes the gauge reading to /data/misc/pocket_battlog/battlog-*.csv.
# It holds a wakelock all through so the rests are counted awake, and sets the property to
# done (or abort) at the end, which makes init release the wakelock.

G=/sys/devices/platform/battery/power_supply/battery/gauge_log
DIR=/data/misc/pocket_battlog
PROP=persist.vendor.pocket.battlog
LOCK=pocket_battlog
POLL_S=10
FIRST_REST_S=3600	# rest at full before the first load
REST_S=2700		# rest after each load; the table maker skips rests under 1200 s
STEP_PCT=5		# charge per load step, % of the charge at full
LOAD_END_MV=3500	# last load step ends here under load
ABORT_MV=3450		# the driver's 0 % voltage; stop the loads at once below it
MIN_SOC=3		# stop the loads at once at or below this level
MAX_STEPS=30
MAX_FAILS=30		# gauge reads failed in a row (5 min) before it gives up
LOAD_MAX_S=3600		# longest load step
FULL_SOC=98		# level needed at unplug to start

umask 022
OUT=$DIR/battlog-$(date +%Y%m%d-%H%M%S).csv
LOADS=
FAILS=0

note() {
	echo "# $(date +%Y-%m-%dT%H:%M:%S) $*" >> "$OUT"
}

stop_loads() {
	for p in $LOADS; do
		kill "$p" 2>/dev/null
	done
	LOADS=
}

finish() {
	stop_loads
	note "$1"
	echo $LOCK > /sys/power/wake_unlock
	setprop $PROP "$2"
	exit 0
}

trap 'stop_loads; echo $LOCK > /sys/power/wake_unlock; exit 0' TERM INT HUP

# read one gauge line into the R_ variables; 1 if the gauge has no reading
read_gauge() {
	line=$(cat $G 2>/dev/null) || return 1
	[ -n "$line" ] || return 1
	oifs=$IFS
	IFS=,
	set -- $line
	IFS=$oifs
	[ $# -eq 10 ] || return 1
	R_T=$1 R_V=$2 R_I=$3 R_CC=$4 R_OCV=$5 R_TEMP=$6 R_SOC=$7 R_RC=$8 R_AD=$9 R_REST=${10}
}

# log one sample as phase $1, step $2; abort after MAX_FAILS failed reads in a row
sample() {
	if ! read_gauge; then
		FAILS=$((FAILS + 1))
		[ $FAILS -ge $MAX_FAILS ] && finish "no gauge reading for $FAILS tries in $1 $2" abort
		return 1
	fi
	FAILS=0
	echo "$1,$2,$R_T,$R_V,$R_I,$R_CC,$R_OCV,$R_TEMP,$R_SOC,$R_RC,$R_AD,$R_REST" >> "$OUT"
}

# rest for $2 s as step $1; abort if the charger goes in
rest() {
	end=$(( $(date +%s) + $2 ))
	while [ "$(date +%s)" -lt "$end" ]; do
		if sample rest "$1" && [ "$R_AD" != 0 ]; then
			finish "charger in during rest $1" abort
		fi
		sleep $POLL_S
	done
}

echo $LOCK > /sys/power/wake_lock
echo "phase,step,t_s,volt_mv,curr_ma,cc_uah,chip_ocv_mv,temp_c,soc,rc_mah,adapter,rest_s" > "$OUT"
note "start, waiting for the charger to be unplugged"

while :; do
	if read_gauge && [ "$R_AD" = 0 ]; then
		break
	fi
	sleep $POLL_S
done
if [ "$R_SOC" -lt $FULL_SOC ]; then
	finish "unplugged at $R_SOC %, charge to full and start again" abort
fi
note "unplugged at $R_SOC %, $R_RC mAh"
STEP_UAH=$(( R_RC * 1000 * STEP_PCT / 100 ))

step=0
rest 0 $FIRST_REST_S
while [ $step -lt $MAX_STEPS ]; do
	step=$((step + 1))
	read_gauge || sleep $POLL_S
	read_gauge || finish "no gauge reading before load $step" abort
	cc0=$R_CC
	note "load $step"
	( while :; do :; done ) &
	LOADS="$LOADS $!"
	( while :; do :; done ) &
	LOADS="$LOADS $!"
	last=0
	load_end=$(( $(date +%s) + LOAD_MAX_S ))
	while :; do
		sleep $POLL_S
		[ "$(date +%s)" -lt "$load_end" ] || finish "load $step ran past $LOAD_MAX_S s" abort
		sample load $step || continue
		if [ "$R_AD" != 0 ]; then
			finish "charger in during load $step" abort
		fi
		if [ "$R_V" -lt $ABORT_MV ] || [ "$R_SOC" -le $MIN_SOC ]; then
			last=1
			break
		fi
		[ "$R_V" -lt $LOAD_END_MV ] && last=1
		[ $((cc0 - R_CC)) -ge "$STEP_UAH" ] && break
		[ $last = 1 ] && break
	done
	stop_loads
	sleep 2
	rest $step $REST_S
	[ $last = 1 ] && break
done
finish "end after $step loads" done
