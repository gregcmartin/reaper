# Build layer
FROM golang:latest AS build

WORKDIR /app

COPY . .

RUN go mod download
RUN go get github.com/playwright-community/playwright-go

ENV GOOS=linux

RUN go build -ldflags="-s -w" -o reaper ./cmd/reaper

# Run layer
FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies including Playwright requirements
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    wget \
    gnupg \
    libglib2.0-0 \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libdbus-1-3 \
    libxcb1 \
    libxkbcommon0 \
    libx11-6 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2t64 \
    && update-ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -d /app -s /bin/bash app

WORKDIR /app
COPY . .
COPY --from=build /app/reaper .
COPY --from=build /app/cmd/reaper/dist ./dist

# Install Playwright browsers
ENV PATH="/app/.cache/ms-playwright/bin:${PATH}"
RUN go run github.com/playwright-community/playwright-go/cmd/playwright install --with-deps chromium

RUN chown -R app /app
USER app

CMD ["./reaper"]
