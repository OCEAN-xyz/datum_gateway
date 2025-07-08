FROM ubuntu AS build
RUN apt update && apt install cmake pkgconf libcurl4-openssl-dev libjansson-dev libmicrohttpd-dev libsodium-dev psmisc -y
COPY . /workdir
WORKDIR /workdir
RUN cmake . && make

FROM ubuntu
RUN apt update && apt install libcurl4-openssl-dev libjansson4 libmicrohttpd-dev libsodium23 -y
WORKDIR /app
COPY --from=build /workdir/datum_gateway /app/
COPY --from=build /workdir/www /app/www/
COPY --from=build /workdir/doc/example_datum_gateway_config.json /app/config/config.json
ENTRYPOINT ["/app/datum_gateway", "--config", "/app/config/config.json"]
