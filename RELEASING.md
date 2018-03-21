# Releasing snyk-docker-analyzer

The github.com/GoogleCloudPlatform/snyk-docker-analyzer uses Container Builder triggers to build and release binaries.
These triggers are setup via the Cloud Console, but the builds they execute live in this repo.

## Continuous Builds

Every commit to master is built and pushed automatically to a GCS location named via the COMMIT_SHA.

```shell
$ gsutil ls gs://snyk-docker-analyzer/builds/
gs://snyk-docker-analyzer/builds/b726215b8b978e1d85257af5c2fd0a6fb8e116fd/

$ gsutil ls gs://snyk-docker-analyzer/builds/b726215b8b978e1d85257af5c2fd0a6fb8e116fd/
gs://snyk-docker-analyzer/builds/b726215b8b978e1d85257af5c2fd0a6fb8e116fd/snyk-docker-analyzer-darwin-amd64.sha256
gs://snyk-docker-analyzer/builds/b726215b8b978e1d85257af5c2fd0a6fb8e116fd/snyk-docker-analyzer-linux-amd64
gs://snyk-docker-analyzer/builds/b726215b8b978e1d85257af5c2fd0a6fb8e116fd/snyk-docker-analyzer-linux-amd64.sha256
gs://snyk-docker-analyzer/builds/b726215b8b978e1d85257af5c2fd0a6fb8e116fd/snyk-docker-analyzer-windows-amd64.exe.sha256
```

The artifacts built and stored are roughly equivalent to the `make cross` target in our Makefile.

The `cloudbuild.yaml` at the project root is used to build these artifdacts.

## Release Build

When a new tag is pushed to Github, a second Container Builder pipeline is executed to build and upload release binaries.
These are stored in another GCS location, in the same bucket.
These artifacts are named via the git TAG name.

```shell
$ gsutil ls gs://snyk-docker-analyzer/
gs://snyk-docker-analyzer/builds/
gs://snyk-docker-analyzer/latest/
gs://snyk-docker-analyzer/v0.2.0/
gs://snyk-docker-analyzer/v0.4.0/
gs://snyk-docker-analyzer/v0.4.1/
gs://snyk-docker-analyzer/v0.5.0/
```

A second, `latest` location is setup as an alias to the latest release.
This upload and aliases is handled automatically via the `cloudbuild-release.yaml` file located at the project root.

## Release Instructions

To perform a release, follow these steps:

1. Select the `commit` to create the release at, preferably from the `master` branch.
2. Create a new git `tag` and matching Github `release`, pointing to this commit.  
  This can be done either through the UI or CLI.
3. Write a descriptive release page.  
  You can use the notes from the last release to help seed the template.
3. Wait for the Container Builder release build to complete.  
 You can follow this in the [UI](https://cloud.google.com/gcr/triggers).
4. Mirror the release artifacts to the Github release page.  
 (Download them from GCS and re-upload them to Github).
