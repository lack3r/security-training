# Security Best Practices for .NET & React – 1 Hour Demo

This repository contains a demo showcasing security best practices for modern web applications built with .NET (backend) and React (frontend). The demo aims to scratch the surface of security best practices and provide practical ideas to improve the security of your applications.

**Duration:** 1 Hour

## Contents

- **Slides:**  
  Presentation slides covering key security concepts and best practices, including secure communication (HTTPS, CORS, security headers), authentication (JWT, cookies), rate limiting, UUIDs for resource IDs, and more.

- **Backend:**  
  A simple ASP.NET Core Web API demonstrating secure authentication, rate limiting, security headers, and resource management using UUIDs.

- **Frontend:**  
  A React application that interacts with the backend for login, secure API calls, and resource creation/retrieval.

## Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- [Node.js](https://nodejs.org/) (preferably the LTS version)
- Git

## Getting Started

1. **Clone the Repository:**

   ```bash
   git clone git@github.com:lack3r/security-training.git
   cd security-training
   ```

2. Start the Slides:
The slides are built with Reveal.js.

   ```
   npm install && npm start
   ```
The slides will be available at: http://localhost:8000/

3. Start the Backend:
   ```
   cd backend
   dotnet run
   ```
The backend will be available at: https://localhost:5001/

4. Start the Frontend:
Open a new terminal, navigate to the frontend folder, install dependencies, and start the application.

   ```
   cd SecurityDemo/frontend
   npm install && npm start
   ```
The frontend will be available at: https://localhost:3000/

Pending Improvements
[ ] Add a section regarding KeyVault integration for managing secrets