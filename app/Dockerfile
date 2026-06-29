FROM node:20-alpine

WORKDIR /app

# Install dependencies from the lockfile for reproducible hands-on builds.
COPY package*.json ./
RUN npm ci

# Copy application code
COPY . .

# Build the application
RUN npm run build

# Remove devDependencies after build
RUN npm prune --production

# Create log directory
RUN mkdir -p /var/log/app

# Expose port
EXPOSE 3000

# Start the application
CMD ["node", "dist/main.js"]

