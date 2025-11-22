import mongoose from "mongoose";

import dotenv from "dotenv";

dotenv.config();


const ConnectionDb = async() => {
  try {
     const conn = await mongoose.connect(process.env.URL);
     console.log(`✅✅ 😏 Database connected successfully `);
     
  } catch (error) {
    console.log(` ❌ error while connecting to there database ${error}`);
  }
}

export default ConnectionDb;