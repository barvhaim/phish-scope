# Official Playwright image — comes with Chromium, Firefox, WebKit + all deps
FROM mcr.microsoft.com/playwright:v1.49.1-jammy

# Set working directory
WORKDIR /app

# Install latest @playwright/mcp
RUN npm install @playwright/mcp@latest

# Ensure browsers match the exact Playwright version used by MCP (recommended)
RUN npx playwright install --with-deps chromium

# Create output directory and give permissions to pwuser
ENV PLAYWRIGHT_MCP_OUTPUT_DIR=/tmp/playwright-output
RUN mkdir -p /tmp/playwright-output && \
    chown -R pwuser:pwuser /tmp/playwright-output && \
    chmod -R 777 /tmp/playwright-output   # sometimes needed for traces/videos

# Use non-root user (already set in official image)
USER pwuser

# No ENTRYPOINT — let docker-compose command: handle everything
# (you can add a minimal one if you want)
# ENTRYPOINT ["npx", "@playwright/mcp"]