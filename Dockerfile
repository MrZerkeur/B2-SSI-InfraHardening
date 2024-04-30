FROM node

COPY website /website

WORKDIR /website

ENV SECRET_KEY=d8141cxkMIaNn5mvvl2A+VYAm40SHYaurBV7riC0FEU=
ENV NODE_ENV=development

RUN npm install

RUN npm install iron-session

CMD ["npm", "run", "dev"]