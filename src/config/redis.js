import Redis from "ioredis";

const redisClient = new Redis({
  host: process.env.REDIS_HOST || "redis",
  port: process.env.REDIS_PORT || 6379
});


export default redisClient;



