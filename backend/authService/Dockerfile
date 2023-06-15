FROM node:18

# Create app directory
WORKDIR /usr/src/app

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY package*.json ./

RUN npm install
# If you are building your code for production
# RUN npm ci --omit=dev

# Bundle app source
COPY . .

ENV PORT=3500

ENV PORT=3500
ENV ACCESS_TOKEN_SECRET=d6f440b2c8598df4cb9716de17da536f537edc9853d2eea1290571513bf15575aa49877085bf595b5cbab4be7f1b11b3228c3caf1efe5a68e1664dc2b43ed806
ENV REFRESH_TOKEN_SECRET=a6d00e3097853699d8b26469e1cf834156aa157698b90536f8f922e24cd291c9221e3362d093a5b562d1acbedf7a6ecc3d07e275650ff398da6acb44ed09d8e9
ENV DATABASE_URI=mongodb+srv://authAdmin:XSTvxPOTzUyxrjDY@cluster0.xfrpvht.mongodb.net/Auth_Service?retryWrites=true&w=majority
ENV REDIS_PORT=19699
ENV REDIS_PASS=U35Z2GaH66iYNcgvOfOsDkRwl4wVeJ3u
ENV REDIS_HOST=redis-19699.c98.us-east-1-4.ec2.cloud.redislabs.com

ENV PRIVATE_KEY_HEX=8377729602cf04daefccc4735ae8ab345f2cec1c9b39714d325b2a81726e92f0

EXPOSE 3500

CMD [ "node", "server.js" ]
