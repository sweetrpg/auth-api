# This is a multi-stage Dockerfile and requires >= Docker 17.05
# https://docs.docker.com/engine/userguide/eng-image/multistage-build/
FROM swift:6.3-jammy AS builder

WORKDIR /build

# Resolve dependencies before copying source, so source-only changes don't invalidate the
# downloaded-dependencies layer.
COPY Package.swift Package.resolved* ./
RUN swift package resolve

COPY . .
RUN swift build -c release --static-swift-stdlib

FROM swift:6.3-jammy-slim

ARG USERNAME=sweetrpg
ARG BUILD_NUMBER=unset
ARG BUILD_JOB=unset
ARG BUILD_SHA=unset
ARG BUILD_DATE=unset
ARG BUILD_VERSION=unset

RUN useradd --user-group --create-home --system --skel /dev/null $USERNAME

WORKDIR /app

RUN mkdir -p /app/bin /app/config
# Package.swift's executable target is named "Run" (Sources/Run/main.swift), not "App" -
# "App" is the library target (Sources/App).
COPY --from=builder /build/.build/release/Run /app/bin/

RUN echo "{\"number\":\"${BUILD_NUMBER}\",\"job\":\"${BUILD_JOB}\",\"sha\":\"${BUILD_SHA}\",\"date\":\"${BUILD_DATE}\",\"version\":\"${BUILD_VERSION}\"}" > /app/config/build-info.json
RUN chown -R ${USERNAME}:${USERNAME} /app

ENV PORT="8080"
ENV VERSION=${BUILD_VERSION}

EXPOSE 8080

USER ${USERNAME}

ENTRYPOINT ["/app/bin/Run"]
CMD ["serve"]
