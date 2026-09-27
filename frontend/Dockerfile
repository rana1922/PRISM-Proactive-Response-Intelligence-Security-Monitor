FROM node:20-alpine AS build

WORKDIR /app

COPY package*.json ./
RUN if [ -f package-lock.json ]; then npm ci || npm install; else npm install; fi

COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 3000

# Nginx SPA & reverse proxy config
COPY frontend/nginx.conf* nginx.conf* /etc/nginx/conf.d/default.conf

CMD ["nginx", "-g", "daemon off;"]
