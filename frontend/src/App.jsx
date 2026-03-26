import { useState } from "react";
import Scanner from "./components/Scanner";
import Header from "./components/Header";
import "./App.css";

export default function App() {
  const [view, setView] = useState("scan"); 

  return (
    <div className="app">
      <Header view={view} setView={setView} scanCount={0} />
      <main className="main">
        {view === "scan" && (
          <Scanner />
        )}
        {view === "history" && (
          <div className="page fade-in">
             <h2>Scan History</h2>
             <p>History component integration goes here.</p>
          </div>
        )}
      </main>
    </div>
  );
}