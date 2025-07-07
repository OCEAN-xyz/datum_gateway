FROM alpine AS build
RUN apk add build-base cmake pkgconf argp-standalone curl-dev jansson-dev libsodium-dev libmicrohttpd-dev psmisc
COPY . /workdir
WORKDIR /workdir
RUN cmake . && make

FROM alpine
RUN apk add libcurl libsodium jansson libmicrohttpd
WORKDIR /app
COPY --from=build /workdir/datum_gateway /app/
COPY --from=build /workdir/www /app/www/
COPY --from=build /workdir/doc/example_datum_gateway_config.json /app/config/config.json
ENTRYPOINT ["/app/datum_gateway", "--config", "/app/config/config.json"]
