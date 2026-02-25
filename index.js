import express from "express";

const app = express();
const PORT = 3000;

// Middleware básico
app.use(express.json());

// Rota simples
app.get("/", (req, res) => {
    res.send("Hello from Express + ES Modules!");
});

// Iniciar servidor
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});


