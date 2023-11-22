INCLUDE PERFETTO MODULE android.startup.startups;

SELECT 
  ftrace_event.ts,
  process.name as process_name, 
  thread.name as thread_name, 
  EXTRACT_ARG(ftrace_event.arg_set_id, "address")  as address,
  EXTRACT_ARG(ftrace_event.arg_set_id, "ip")  as ip
FROM ftrace_event
      left join thread ON ftrace_event.utid = thread.utid
      left join process ON thread.upid = process.upid
WHERE 
  ftrace_event.name = 'page_fault_user' 
  AND ftrace_event.ts >= (SELECT MIN(ts) from android_startups WHERE package = process.name)
  AND ftrace_event.ts <= (SELECT MIN(ts_end) from android_startups WHERE package = process.name)
  AND process.name = 'com.google.android.youtube' 
ORDER BY ts ASC
