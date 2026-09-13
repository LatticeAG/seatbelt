// Guard subprocess entry: `node dist/guard-entry.js <sock> <cgroup_root>
// <emergency_file>`. The guard attaches to daemon-created cgroup trees by
// convention, drives GuardCore on the monotonic clock, and treats channel EOF
// as control loss.

import { runGuardEntry } from "./guardproc.js";

const [sock, cgroupRoot, emergencyPath] = process.argv.slice(2);
if (!sock || !cgroupRoot || !emergencyPath) {
  process.stderr.write("usage: guard-entry <sock> <cgroup_root> <emergency_file>\n");
  process.exit(2);
}
runGuardEntry(sock, cgroupRoot, emergencyPath);
