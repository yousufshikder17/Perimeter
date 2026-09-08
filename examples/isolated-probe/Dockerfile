FROM node:22-alpine
COPY worker.mjs /worker.mjs
USER 65532:65532
ENTRYPOINT ["node", "/worker.mjs"]
