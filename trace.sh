set -ueo pipefail
# Root is required for collecting `/proc/pid/map`
adb root

PACKAGE=$1

# Ensure application is killed first
adb shell am force-stop $PACKAGE

# Drop page cache
adb shell setprop perf.drop_caches 3

# Collect `page_faults_user` tracepoint for x86 
record_android_trace -c ftrace.config -o traces/user_page_faults.pftrace -n

# Replace package name in SQL
cp user_page_faults.sql /tmp/user_page_faults.sql
sed -i -e "s/PROCESS_NAME/$PACKAGE/g" /tmp/user_page_faults.sql

# Extract out the page_faults_user ftrace events into a csv file
./trace_processor -q /tmp/user_page_faults.sql traces/user_page_faults.pftrace > user_page_faults.csv

# Extract the application's memory mappings
package_pid=$(adb shell "pidof $PACKAGE")
adb shell "cat /proc/$package_pid/maps" > maps.txt

# Associate page fault addresses with an underlying file
# Furthermore, if the file accessed is an APK, find the underlying file within.
python3 process.py