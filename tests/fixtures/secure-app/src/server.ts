import express from "express";
import helmet from "helmet";
import cors from "cors";

const app = express();

app.use(helmet());
app.use(cors({ origin: "https://myapp.com" }));

app.get("/api/users/:id", async (req, res) => {
  const userId = req.params.id;
  // Parameterized query - safe
  const result = await pool.query("SELECT * FROM users WHERE id = $1", [userId]);
  res.json(result.rows);
});

app.listen(process.env.PORT || 3000);
