FROM node

COPY website /website

WORKDIR /website

RUN npm install

RUN npm install iron-session

CMD ["npm", "run", "dev"]