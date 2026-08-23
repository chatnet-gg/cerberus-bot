# Copyright (c) 2026 ChatNet (sh). MIT licensed, see LICENSE.
#
# Cerberus -- ChatNet's ban/kill audit bot (see main.go's own header
# comment for the full reasoning, and github.com/Libera-Chat/beryllia
# for the project that inspired it). Hand-rolled IRC client over stdlib
# only, same as every other bot in this project -- the one real external
# dependency here is the Postgres driver (lib/pq), not an IRC library.

FROM golang:1.22-alpine AS build

WORKDIR /app
COPY go.mod ./
COPY main.go irc.go parse.go db.go commands.go ./
RUN go mod tidy && go build -o /opt/cerberus/cerberus .

FROM alpine:latest

RUN adduser -D -h /home/cerberus cerberus

COPY --from=build /opt/cerberus/cerberus /opt/cerberus/cerberus

USER cerberus
WORKDIR /home/cerberus
ENTRYPOINT ["/opt/cerberus/cerberus"]
