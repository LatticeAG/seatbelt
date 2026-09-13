/* seatbelt-peercred: print the peer uid of the unix socket on fd 3.
 *
 * The daemon launches this helper with the connected control-socket fd
 * inherited as fd 3. SO_PEERCRED must be read by a process that can see the
 * socket; Node's net.Socket does not expose it, so we take the fd.
 *
 * Usage: peercred            (reads fd 3, prints "<uid>" on stdout)
 * Exit: 0 ok; 2 error.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

struct ucred_fallback {
  pid_t pid;
  uid_t uid;
  gid_t gid;
};

int main(void) {
  struct ucred_fallback cred;
  socklen_t len = sizeof(cred);
  memset(&cred, 0, sizeof(cred));
  if (getsockopt(3, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
    fprintf(stderr, "SO_PEERCRED: %s\n", strerror(errno));
    return 2;
  }
  printf("%ld\n", (long)cred.uid);
  return 0;
}
