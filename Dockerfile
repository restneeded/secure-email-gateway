FROM node:20-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
COPY prisma ./prisma
RUN --mount=type=cache,target=/root/.npm \
    npm ci --omit=dev && npx prisma generate

FROM node:20-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
RUN addgroup -S app && adduser -S app -G app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY prisma ./prisma
COPY src ./src
COPY public ./public
COPY scripts ./scripts
RUN mkdir -p /app/data /app/storage && chown -R app:app /app
USER app
EXPOSE 2525 3010
CMD ["node", "src/portal.js"]
