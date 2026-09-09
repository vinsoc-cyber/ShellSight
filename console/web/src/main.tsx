import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Cases } from './routes/Cases'
import { Generate } from './routes/Generate'
import { RuleEditor } from './routes/RuleEditor'
import { Rules } from './routes/Rules'
import { RuleSets } from './routes/RuleSets'
import { Scan } from './routes/Scan'
import { Scans } from './routes/Scans'
import './app.css'

const root = document.getElementById('root')
if (!root) throw new Error('#root missing from index.html')

createRoot(root).render(
  <StrictMode>
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Cases />} />
          <Route path="/cases/:caseID" element={<Scans />} />
          <Route path="/scans/:scanID" element={<Scan />} />
          <Route path="/rules" element={<Rules />} />
          <Route path="/rules/new" element={<RuleEditor />} />
          <Route path="/rules/:ruleID" element={<RuleEditor />} />
          <Route path="/rulesets" element={<RuleSets />} />
          <Route path="/generate" element={<Generate />} />
        </Route>
      </Routes>
    </BrowserRouter>
  </StrictMode>,
)
