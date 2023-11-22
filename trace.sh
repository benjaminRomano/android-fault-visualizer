# Root is required for collecting `/proc/pid/map`
adb root

# Ensure application is killed first
adb shell am force-stop com.google.android.youtube

# Drop page cache
adb shell setprop perf.drop_caches 3

# Collect `page_faults_user` tracepoint for x86 
record_android_trace -c ftrace.config -o traces/user_page_faults.pftrace -n
# Extract out the ftrace events into a csv file
./trace_processor -q user_page_faults.sql traces/user_page_faults.pftrace > user_page_faults.csv

# Extract the application's memory mappings
adb shell 'cat /proc/$(pidof com.google.android.youtube)/maps' > maps.txt

# Associate page fault addresses with an underlying file
# Furthermore, if the file accessed is an APK, find the underlying file within.
python process.py