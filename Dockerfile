FROM golang:1-alpine AS builder

# GOPROXY is disabled by default, use:
# docker build --build-arg GOPROXY="https://goproxy.io" ...
# to enable GOPROXY.
ARG GOPROXY=""

ENV GOPROXY ${GOPROXY}

# Assuming the repository path remains the same, but the internal project name changed.
# If the GitHub repository itself also changed to 'apernet/xless', you'll need to update this line.
COPY . /go/src/github.com/XLESSGo/XLESS

# Assuming the work directory within the builder image remains the same for the source code.
WORKDIR /go/src/github.com/XLESSGo/XLESS

RUN set -ex \
    && apk add git build-base bash python3 \
    && python hyperbole.py build -r \
    # IMPORTANT: Changed 'hysteria-*' to 'xless-*' and '/go/bin/hysteria' to '/go/bin/xless'
    # This assumes 'hyperbole.py build -r' now produces a file named 'xless-*'
    # If the exact filename is known (e.g., 'xless-linux-amd64'), it's better to use that.
    && mv ./build/xless-* /go/bin/xless

# multi-stage builds to create the final image
FROM alpine AS dist

# set up nsswitch.conf for Go's "netgo" implementation
# - https://github.com/golang/go/blob/go1.9.1/src/net/conf.go#L194-L275
# - docker run --rm debian:stretch grep '^hosts:' /etc/nsswitch.conf
RUN if [ ! -e /etc/nsswitch.conf ]; then echo 'hosts: files dns' > /etc/nsswitch.conf; fi

# bash is used for debugging, tzdata is used to add timezone information.
# Install ca-certificates to ensure no CA certificate errors.
#
# Do not try to add the "--no-cache" option when there are multiple "apk"
# commands, this will cause the build process to become very slow.
RUN set -ex \
    && apk upgrade \
    && apk add bash tzdata ca-certificates \
    && rm -rf /var/cache/apk/*

# IMPORTANT: Changed '/go/bin/hysteria' to '/go/bin/xless' and '/usr/local/bin/hysteria' to '/usr/local/bin/xless'
COPY --from=builder /go/bin/xless /usr/local/bin/xless

# IMPORTANT: Changed 'hysteria' to 'xless'
ENTRYPOINT ["xless"]
