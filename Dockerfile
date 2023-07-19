FROM postgres:12-alpine

RUN apk --no-cache add bash postgresql12-client

RUN addgroup -S didserver && \
    adduser -S didserver -G didserver
USER didserver

RUN mkdir /home/didserver/app

WORKDIR /home/didserver/app

COPY --chown=didserver:didserver . .

CMD ["./scripts/start"]
