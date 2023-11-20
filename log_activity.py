
import datetime

class log_activity:

    def log_activity(username, activity):
        log_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{log_time}] User '{username}' performed activity: '{activity}'\n"
        
        log_file_path = 'activity_log.txt'  # Change the file path as needed
        
        # Open the log file in append mode and write the log entry
        with open(log_file_path, 'a') as log_file:
            log_file.write(log_entry)

    # # Example usage:
    # username = 'JohnDoe'
    # activity = 'Logged in'

    # log_activity(username, activity)
