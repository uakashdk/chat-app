import express from "express";

import dotenv from "dotenv";

import cors from "cors";
import ConnectionDb from "./config/db.js";
import { Server as SocketServer } from "socket.io";
import http from "http";
import redisClient from "./config/redis.js";
import AuthRoutes from "./routes/authRoutes.js"


dotenv.config();

const app = express();


const PORT = process.env.PORT || 8080;

ConnectionDb();

redisClient.on("connect", () => {
  console.log("✅ Redis connected successfully");
});
redisClient.on("error", (err) => {
  console.error("❌ Redis connection error:", err);
});


app.use(express.json());

app.use(cors({
  origin: "*",
  credentials: true,
  allowedHeaders: ["Content-Type", "Authorization"],
  optionsSuccessStatus: 200,
}));

const server = http.createServer(app);
const io = new SocketServer(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});


io.on("connection", (socket) => {
  console.log(`🔗 New client connected: ${socket.id}`);

  socket.on("joinRoom", (roomId) => {
    socket.join(roomId);
    console.log(`User joined room: ${roomId}`);
  });

  socket.on("sendMessage", (data) => {
    const { roomId, message, sender } = data;
    io.to(roomId).emit("receiveMessage", { message, sender, createdAt: new Date() });
  });

  socket.on("disconnect", () => {
    console.log(`❌ Client disconnected: ${socket.id}`);
  });
});

app.use("/api/v1/auth",AuthRoutes);


server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});


