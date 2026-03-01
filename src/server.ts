import app from "./app.js";
import { ENV } from "./config/env.js";
import pool from "./config/database.js";

async function start() {
  await pool.connect();

  app.listen(ENV.PORT, () => {
    console.log(`Server running on port ${ENV.PORT}`);
  });
}

start();