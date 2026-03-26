import { useState } from "react";
import { Routes, Route, useNavigate } from "react-router-dom";
import Scanner from "./components/Scanner";
import Header from "./components/Header";
import Archive from "./components/Archive";
import ScanResultsPage from "./components/ScanResultsPage";
import ReportView from "./components/ReportView";
import "./App.css";

export default function App() {
  const [view, setView] = useState("scan");
  const navigate = useNavigate();

  return (
    <div className="app">
      <Header view={view} setView={setView} scanCount={0} />
      <main className="main">
        <Routes>
          <Route path="/" element={<Scanner />} />
          <Route path="/scanner" element={<Scanner />} />
          <Route path="/archive" element={<Archive />} />
          <Route path="/scan/backend/:id" element={<ScanResultsPage />} />
          <Route path="/scan/:source/:id" element={<ReportView />} />
          <Route path="/report/:source/:id/:fmt" element={<ReportView />} />
        </Routes>
      </main>
    </div>
  );
}