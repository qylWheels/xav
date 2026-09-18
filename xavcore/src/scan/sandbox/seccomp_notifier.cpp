#include "seccomp_notifier.h"

#include <seccomp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <system_error>

namespace xavcore {
namespace {
std::error_code last_error() { return {errno, std::system_category()}; }
}  // namespace

namespace scan {
namespace sandbox {
outcome::result<void> Supervisor::install_and_hand_over(int handover_fd) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_NOTIFY);
    if (ctx == nullptr) {
        // libseccomp before 2.5 does not know SCMP_ACT_NOTIFY.
        return std::make_error_code(std::errc::function_not_supported);
    }

    // Allow sendmsg() on the hand-over socket. Without this rule the hand-over
    // itself would be reported and block, because the supervisor does not have
    // the notification fd yet.
    int rc = seccomp_rule_add(
        ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendmsg), 1,
        SCMP_A0(SCMP_CMP_EQ, static_cast<scmp_datum_t>(handover_fd)));
    if (rc < 0) {
        seccomp_release(ctx);
        return std::error_code(-rc, std::system_category());
    }

    rc = seccomp_load(ctx);
    if (rc < 0) {
        seccomp_release(ctx);
        return std::error_code(-rc, std::system_category());
    }

    const int notify_fd = seccomp_notify_fd(ctx);
    if (notify_fd < 0) {
        // The filter is already loaded. Releasing the context here closes fds,
        // and that close would be reported and block. Leave it behind instead.
        return std::error_code(-notify_fd, std::system_category());
    }

    // Everything below is reported, so send the fd before anything else.
    auto sent = send_fd(handover_fd, notify_fd);

    // Releasing closes the notify fd. That close is reported and answered like
    // any other syscall. The supervisor already has its own copy by now.
    seccomp_release(ctx);
    return sent;
}

outcome::result<void> Supervisor::send_fd(int sock, int fd) {
    char byte = 0;
    struct iovec io{.iov_base = &byte, .iov_len = sizeof(byte)};
    char control[CMSG_SPACE(sizeof(int))] = {};
    struct msghdr message = {};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);

    struct cmsghdr* header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    std::memcpy(CMSG_DATA(header), &fd, sizeof(fd));

    if (::sendmsg(sock, &message, MSG_NOSIGNAL) < 0) {
        return last_error();
    }
    return outcome::success();
}

outcome::result<int> Supervisor::receive_fd(int sock) {
    char byte = 0;
    struct iovec io{.iov_base = &byte, .iov_len = sizeof(byte)};
    char control[CMSG_SPACE(sizeof(int))] = {};
    struct msghdr message = {};
    message.msg_iov = &io;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);

    // Blocks until the sandboxed process sends the fd or dies. A dead process
    // closes its end of the socket, so this does not wait forever.
    ssize_t received = ::recvmsg(sock, &message, 0);
    while (received < 0 && errno == EINTR) {
        received = ::recvmsg(sock, &message, 0);
    }
    if (received < 0) {
        return last_error();
    }

    struct cmsghdr* header = CMSG_FIRSTHDR(&message);
    if (header == nullptr || header->cmsg_type != SCM_RIGHTS ||
        header->cmsg_len != CMSG_LEN(sizeof(int))) {
        return std::make_error_code(std::errc::protocol_error);
    }

    int fd = -1;
    std::memcpy(&fd, CMSG_DATA(header), sizeof(fd));
    return fd;
}

outcome::result<NotifyResult> Supervisor::serve(
    int notify_fd, ISandboxSyscallHandler& handler) {
    struct seccomp_notif* request = nullptr;
    struct seccomp_notif_resp* response = nullptr;
    int rc = seccomp_notify_alloc(&request, &response);
    if (rc < 0) {
        return std::error_code(-rc, std::system_category());
    }

    // The kernel requires the request buffer to be all zero before each
    // receive, so it is cleared below. The size comes from the kernel and not
    // from this build, in case the two differ.
    struct seccomp_notif_sizes sizes = {};
    std::size_t request_size = sizeof(*request);
    if (::syscall(SYS_seccomp, SECCOMP_GET_NOTIF_SIZES, 0, &sizes) == 0) {
        request_size = sizes.seccomp_notif;
    }

    NotifyResult result;

    while (true) {
        std::memset(request, 0, request_size);

        // The raw ioctl is used here instead of seccomp_notify_receive(). That
        // libseccomp call turns ENOENT and EINTR into ECANCELED, and the two
        // must be told apart: ENOENT means the target is gone, EINTR means a
        // signal arrived and the wait must be retried.
        if (::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, request) < 0) {
            if (errno == ENOENT) {
                // No task uses the filter any more, so the target is gone.
                break;
            }
            if (errno == EINTR) {
                continue;
            }
            const int error = errno;
            seccomp_notify_free(request, response);
            return std::error_code(error, std::system_category());
        }

        Syscall syscall;
        syscall.id = request->id;
        syscall.pid = request->pid;
        syscall.syscall_id = static_cast<std::int32_t>(request->data.nr);
        for (std::size_t i = 0; i < 6; ++i) {
            syscall.args[i] = request->data.args[i];
        }

        const SyscallResult answer = handler.handle(syscall);

        response->id = request->id;
        // flags = 0 means the kernel does not run the syscall. It only returns
        // the value below.
        response->flags = 0;
        response->error = answer.error;
        response->val = answer.value;

        if (::ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, response) < 0) {
            if (errno == ENOENT) {
                // The task died between the receive and the answer.
                continue;
            }
            const int error = errno;
            seccomp_notify_free(request, response);
            return std::error_code(error, std::system_category());
        }
        ++result.answered;
    }

    seccomp_notify_free(request, response);
    return result;
}
}  // namespace sandbox
}  // namespace scan
}  // namespace xavcore
