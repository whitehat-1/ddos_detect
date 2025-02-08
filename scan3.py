import time
import os

def follow(thefile):
    """
    Generator function that yields new lines in a file.
    """
    thefile.seek(0, os.SEEK_END)  # Go to the end of the file
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)  # Sleep briefly
            continue
        yield line

def parse_alert(line):
    """
    Parses a single line of Snort log data to extract key details.

    Example log entry:

    04/11-00:06:22.226416  [] [1:527:8] BAD-TRAFFIC same SRC/DST [] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 0.0.0.0:68 -> 255.255.255.255:67

    Returns a formatted string with essential alert information.
    """
    parts = line.split("  ")
    timestamp = parts[0].strip()
    msg_parts = parts[2].split(']')  # Split on ']' to isolate parts of the message
    sid = msg_parts[0].split(':')[1].strip()
    rev = msg_parts[1].strip()
    msg = msg_parts[2][1:].strip()
    classification = msg_parts[3].split(':')[1].strip()
    priority = msg_parts[4].split(':')[1].strip()
    protocol = parts[3][1:].split(' ')[0].strip()
    src_dst = parts[3].split('}')[1].strip()

    return f"Time: {timestamp}, SID: {sid}, Rev: {rev}, Msg: {msg}, Class: {classification}, Priority: {priority}, Protocol: {protocol}, Traffic: {src_dst}"

def main():
    log_file_path = 'C:\Users\Admin\Desktop\ddos_detect'  # Update with your Snort log file path

    try:
        with open(log_file_path, "r") as log_file:
            log_lines = follow(log_file)
            for line in log_lines:
                alert = parse_alert(line)
                print(alert)  # Display the alert

    except FileNotFoundError:
        print(f"The log file {log_file_path} does not exist.")

if _name_ == "_main_":
    main()