FROM alpine:3.18

RUN apk add --no-cache curl

COPY ./obligator /obligator/obligator

VOLUME ["/data"]

VOLUME ["/api"]

EXPOSE 1616

ENTRYPOINT ["/obligator/obligator"]

CMD ["-storage-dir", "/data", "-behind-proxy", "true"]
