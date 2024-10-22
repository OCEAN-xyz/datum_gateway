FROM debian:latest

RUN apt-get update && apt-get install -y \
    build-essential cmake gcc g++ \
    pkg-config libjansson-dev libmicrohttpd-dev libsodium-dev libcurl4-openssl-dev

WORKDIR /app

COPY . .

RUN cmake . && make

CMD ["./datum_gateway"]
