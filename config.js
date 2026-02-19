import dotenv from "dotenv";

// Load environment variables first
dotenv.config();

export const config = {
  PORT: process.env.PORT || 3000,
  API_KEY: process.env.API_KEY,
  OPENAI_API_KEY: process.env.OPENAI_API_KEY,
  FINAL_CALLBACK_URL: process.env.FINAL_CALLBACK_URL
};