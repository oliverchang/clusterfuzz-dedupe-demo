from dataclasses import dataclass
import sys

from clusterfuzz import stacktraces
from clusterfuzz.stacktraces.crash_comparer import CrashComparer

@dataclass
class Stacktrace:
  path: str
  stacktrace: str
  crash_state: str


def main():
  traces = []

  for path in sys.argv[1:]:
    with open(path) as f:
      stacktrace = f.read()

    # Parse each stacktrace into a unique key (the "crash state").
    # ClusterFuzz picks the "top 3" most interesting frames from the stacktrace for this.
    # Common C and standard library functions etc are excluded from this.
    stack_parser = stacktraces.StackParser(symbolized=True,
                                           detect_ooms_and_hangs=True,
                                           include_ubsan=True)
    data = stack_parser.parse(stacktrace)
    if not data.crash_state:
      print('failed to parse ' + path)
      continue

    print(path, 'parsed as:')
    print(data.crash_state)

    traces.append(Stacktrace(path, stacktrace, data.crash_state))

  # (Optional) Run similarity grouping on the crash_state to further deduplicate similar
  # but slightly different stacktraces. This compares each crash state against every other one.
  unique_stacktraces = {}
  for stacktrace in traces:
    is_unique = True
    for unique in unique_stacktraces.keys():
      if CrashComparer(stacktrace.crash_state, unique).is_similar():
        is_unique = False
        unique_stacktraces[unique].append(stacktrace)
        break

    if is_unique:
      unique_stacktraces[stacktrace.crash_state] = [stacktrace]


  for crash_state, traces in unique_stacktraces.items():
    print('crash_state:', crash_state.replace('\n', '-'), 'has', len(traces), 'matching stacktraces')
    for trace in traces:
      print('\t', trace.path, ':', trace.crash_state.replace('\n', '-'))


if __name__ == '__main__':
  main()
