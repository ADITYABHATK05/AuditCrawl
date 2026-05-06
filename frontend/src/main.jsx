import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom"; // Import the Router
import "./App.css";
import "./tailwind.css";
import App from "./App.jsx";
import { ToastProvider } from "./components/ToastProvider";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <BrowserRouter> 
      <ToastProvider>
        <App />
      </ToastProvider>
    </BrowserRouter>
  </StrictMode>
);