load("@io_bazel_rules_go//go:def.bzl", "go_binary", "go_library", "go_prefix")
load("@bazel_gazelle//:def.bzl", "gazelle")

gazelle(
    name = "gazelle",
    external = "vendored",
    prefix = "github.com/snyk/snyk-docker-analyzer",
)

go_prefix("github.com/snyk/snyk-docker-analyzer")

go_library(
    name = "go_default_library",
    srcs = ["main.go"],
    importpath = "github.com/snyk/snyk-docker-analyzer",
    visibility = ["//visibility:private"],
    deps = [
        "//cmd:go_default_library",
        "//vendor/github.com/pkg/profile:go_default_library",
    ],
)

go_binary(
    name = "snyk-docker-analyzer",
    embed = [":go_default_library"],
    importpath = "github.com/snyk/snyk-docker-analyzer",
    visibility = ["//visibility:public"],
)
