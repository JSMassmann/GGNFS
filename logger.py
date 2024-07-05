import sys

def log(message, c1, c2, title, footer, quiet, *logfiles):
  if not quiet:
    print(f"\x1b[1;{c1}m{title}\x1b[0;{c2}m {message}\x1b[1;{c1}m{footer}\x1b[0m")
  for logfile in logfiles:
    try:
      logs = open(logfile, "at")
      logs.write(f"{title} {message}{footer}\n")
      logs.close()
    except Exception:
      print(f"\x1b[1;91mThe file {logfile} could not be opened.\x1b[0m")
      sys.exit(-1)

def error(message, *logfiles):
  log(message, 31, 91, "Error:", "", False, *logfiles)
  sys.exit(-1)

def warn(message, safe, *logfiles):
  log(message, 33, 33, "Warning:", "", False, *logfiles)
  if safe:
    log("Exiting.", 32, 92, "Safe mode:", "", *logfiles)
    sys.exit(-1)

def log_header(message, quiet, *logfiles):
  log(message.upper(), 35, 35, "==========", " ==========", quiet, *logfiles)

def log_content(message, quiet, *logfiles):
  log(message, 36, 96, ">>>", "", quiet, *logfiles)