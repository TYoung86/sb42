FROM mhart/alpine-node:base

ADD app /app

EXPOSE 80 443 9001

CMD ["node", "/app/server.js"]