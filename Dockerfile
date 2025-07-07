FROM alpine AS build
RUN apk add build-base cmake pkgconf argp-standalone curl-dev jansson-dev libsodium-dev libmicrohttpd-dev psmisc
COPY . /workdir
WORKDIR /workdir
RUN cmake . && make

FROM alpine
RUN apk add libcurl libsodium jansson libmicrohttpd
COPY --from=build /workdir/datum_gateway /usr/local/bin/datum_gateway
ENTRYPOINT ["/usr/local/bin/datum_gateway", "-c", "/etc/datum_gateway_config.json"]
