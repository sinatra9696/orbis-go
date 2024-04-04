FROM golang:1.21-bookworm as builder

# Setup env and dev tools
RUN apt update &&\
    apt-get install --yes git make

WORKDIR /app

# Cache deps
COPY go.* /app/
RUN go mod download

# Build
COPY . /app
#ENV GOFLAGS='-buildvcs=false'
RUN --mount=type=cache,target=/root/.cache make build


# Deployment entrypoint
FROM debian:bookworm-slim

RUN useradd -ms /bin/bash node
USER node

COPY --from=builder /app/build/orbisd /usr/local/bin/orbisd

ENTRYPOINT ["orbisd"]