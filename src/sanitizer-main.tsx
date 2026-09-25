import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import SanitizerApp from './SanitizerApp'
import './App.css'
import './sanitizer.css'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <SanitizerApp />
  </StrictMode>,
)
