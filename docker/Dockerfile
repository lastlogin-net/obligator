FROM alpine:3.18

RUN apk add --no-cache curl

COPY ./obligator /obligator/obligator

VOLUME ["/data"]

EXPOSE 1616

ENTRYPOINT ["/obligator/obligator"]

CMD ["-storage-path", "/data/obligator_storage.json"]
