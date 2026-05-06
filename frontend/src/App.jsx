import { Routes, Route, useLocation } from "react-router-dom";
import { AnimatePresence, motion } from "framer-motion";
import Scanner from "./components/Scanner";
import Header from "./components/Header";
import Archive from "./components/Archive";
import ScanResultsPage from "./components/ScanResultsPage";
import ReportView from "./components/ReportView";
import "./App.css";

export default function App() {
  const location = useLocation();

  return (
    <div className="app min-h-screen bg-gradient-to-b from-slatebg-950 via-slatebg-900 to-slatebg-950">
      <Header scanCount={0} />
      <main className="main mx-auto w-full max-w-6xl px-4 py-8 md:px-6 md:py-10">
        <AnimatePresence mode="wait">
          <motion.div
            key={location.pathname}
            initial={{ opacity: 0, y: 14 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.25, ease: "easeOut" }}
          >
            <Routes location={location}>
              <Route path="/" element={<Scanner />} />
              <Route path="/scanner" element={<Scanner />} />
              <Route path="/archive" element={<Archive />} />
              <Route path="/scan/backend/:id" element={<ScanResultsPage />} />
              <Route path="/scan/:source/:id" element={<ReportView />} />
              <Route path="/report/:source/:id/:fmt" element={<ReportView />} />
            </Routes>
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}