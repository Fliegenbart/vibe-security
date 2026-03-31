import express from "express";
import cors from "cors";

const app = express();

// Permissive CORS - should be caught
app.use(cors());

// No security middleware here

app.listen(3000);
