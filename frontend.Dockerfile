# Stage 1: Build the React Application
FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy source code
COPY . .

# Build the app for production (telling it where to find the API)
ENV VITE_API_BASE_URL=http://localhost:8000
RUN npm run build

# Stage 2: Serve with Nginx
FROM nginx:alpine

# Copy the compiled React build from Stage 1 into the Nginx web directory
COPY --from=builder /app/dist /usr/share/nginx/html

# Expose HTTP port
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]