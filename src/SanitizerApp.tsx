import { useState } from 'react';

import goatImg from './assets/goat-header.webp';
import { getRunMode } from './run-mode';
import { SanitizeWizard } from './sanitize-wizard';

// Standalone "Sample Sanitizer" app — a second build target of this repo (NOT a fork).
// It reuses the exact SanitizeWizard screens the pack generator uses, so any change to
// those screens flows into both apps. It runs with NO AI: the whole module graph from
// here is provably free of ai-client / ai-budget / schematizer / provider SDKs
// (enforced by tests/sanitizer-ai-free-test.mjs), and publishing (which needs a token +
// the backend) is off — the only outputs are the shared worker-group library, a
// worker-group sample, and a local download.
export function SanitizerApp() {
  const runMode = getRunMode();
  // Remount the wizard to start a fresh sanitisation. `open` toggling false→true is what
  // resets the wizard's in-memory state (and drops the last copy of the original), so a
  // key bump is the clean "sanitize another" — nothing sanitised is carried across.
  const [epoch, setEpoch] = useState(0);
  const restart = () => setEpoch(e => e + 1);

  return (
    <div className="sanitizer-app">
      {/* Same hero header as the Pack Generator (goat + banner), adapted to this app:
          the badge says AI-Free instead of AI-Powered, and the disclaimer is about
          local, pattern-based sanitisation rather than AI-generated output. */}
      <div className="hero-banner sanitizer-hero">
        <div className="hero-goat">
          <img src={goatImg} alt="Cribl Goat" className="goat-icon" />
          <span className="hero-badge sanitizer-badge">AI-Free</span>
        </div>
        <div className="hero-text">
          <h2 className="hero-title">Sample Sanitizer <span className="build-number">v{APP_VERSION} · build {BUILD_NUMBER}</span></h2>
          <p className="hero-subtitle">Turn a real log sample into a shareable, de-identified one — entirely on-box, no AI.</p>
        </div>
        <div className="hero-disclaimer">
          <svg viewBox="0 0 16 16" className="disclaimer-icon"><path d="M8 1a7 7 0 1 0 0 14A7 7 0 0 0 8 1zm0 2.5a1 1 0 1 1 0 2 1 1 0 0 1 0-2zM6.5 7h3l-.5 5h-2L6.5 7z" fill="currentColor"/></svg>
          <p>This tool sanitises samples <strong>locally in your browser</strong> — no AI is used and your original log never leaves the page. Detection is pattern-based and best-effort, so <strong>always review the redactions</strong> before you download or save to the shared library, and confirm no sensitive data remains.</p>
        </div>
      </div>
      <SanitizeWizard
        key={epoch}
        open
        embedded
        runMode={runMode}
        canPublish={false}
        onClose={restart}
        onLibraryChanged={() => { /* saved to the shared library — the wizard shows the result */ }}
      />
    </div>
  );
}

export default SanitizerApp;
