// SPDX-License-Identifier: Apache-2.0
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import '@tirbase/console-design-system/styles.css';
import './styles.css';
import { App } from './App';
import { SessionProvider } from './session';
import { PosProvider } from './pos/store';

const root = document.getElementById('root');
if (!root) throw new Error('missing #root');

createRoot(root).render(
  <StrictMode>
    <SessionProvider>
      <PosProvider>
        <App />
      </PosProvider>
    </SessionProvider>
  </StrictMode>,
);
