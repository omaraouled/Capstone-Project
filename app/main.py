import argparse
from .collectors import collect_file, collect_linux_syslog, collect_cloudwatch
from .config import CLOUDWATCH_LOG_GROUP
from .pipeline import process_raw_events

def main():
    parser = argparse.ArgumentParser(description="Security Analysis and Detection pipeline")
    parser.add_argument("--file", help="Path to a log file")
    parser.add_argument("--syslog", action="store_true", help="Read default Linux syslog/auth log files")
    parser.add_argument("--cloudwatch", action="store_true", help="Collect recent CloudWatch events")
    parser.add_argument("--log-group", default=CLOUDWATCH_LOG_GROUP)
    parser.add_argument("--start-minutes", type=int, default=60)
    parser.add_argument("--region", default=None)
    args = parser.parse_args()

    raw_events = []
    if args.file:
        raw_events.extend(collect_file(args.file))
    if args.syslog:
        raw_events.extend(collect_linux_syslog())
    if args.cloudwatch:
        raw_events.extend(collect_cloudwatch(args.log_group, args.start_minutes, args.region))
    if not (args.file or args.syslog or args.cloudwatch):
        parser.error("Choose at least one source: --file, --syslog, or --cloudwatch")

    result = process_raw_events(raw_events)
    print(f"Processed: {result['processed']}; invalid: {result['invalid']}; alerts: {len(result['alerts'])}")

if __name__ == "__main__":
    main()
