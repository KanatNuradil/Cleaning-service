# SparkClean Backend

A Node.js backend API for the SparkClean cleaning service with user authentication and order management.

## Features

- User registration and authentication (JWT)
- Order management with SQLite database
- Password hashing with bcrypt
- Input validation with Joi
- Rate limiting and security headers
- CORS enabled for frontend integration

## Setup

1. Install dependencies:
```bash
npm install
```

2. Start the server:
```bash
npm start
```

For development with auto-restart:
```bash
npm run dev
```

3. The server will run on `http://localhost:3000`

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user

### Orders
- `POST /api/orders` - Create new order (requires authentication)
- `GET /api/orders` - Get user's orders (requires authentication)

### Health
- `GET /api/health` - Health check

## Database

The application uses SQLite with two main tables:
- `customers` - User account information
- `orders` - Cleaning service orders

## Environment Variables

- `PORT` - Server port (default: 3000)
- `JWT_SECRET` - Secret key for JWT tokens (default: 'your-super-secret-jwt-key-change-in-production')

## Security Features

- Password hashing with bcrypt
- JWT token authentication
- Rate limiting (100 requests per 15 minutes)
- Security headers with Helmet
- Input validation and sanitization
- CORS protection
