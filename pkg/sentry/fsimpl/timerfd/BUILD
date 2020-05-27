load("//tools:defs.bzl", "go_library")

licenses(["notice"])

go_library(
    name = "timerfd",
    srcs = ["timerfd.go"],
    visibility = ["//pkg/sentry:internal"],
    deps = [
        "//pkg/context",
        "//pkg/sentry/fs/lock",
        "//pkg/sentry/kernel/time",
        "//pkg/sentry/vfs",
        "//pkg/sentry/vfs/lock",
        "//pkg/syserror",
        "//pkg/usermem",
        "//pkg/waiter",
    ],
)
