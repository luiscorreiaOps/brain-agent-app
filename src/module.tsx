import React from 'react';
import { AppPlugin, AppRootProps } from '@grafana/data';
import { BrainConfig } from './components/BrainConfig';
import { BrainHub } from './pages/BrainHub';

function AppRoot(props: AppRootProps) {
  // Brain Agent uses BrainHub as its main page (shows status and controls for zero-config features).
  return <BrainHub />;
}

export const plugin = new AppPlugin<{}>()
  .setRootPage(AppRoot)
  .addConfigPage({
    title: 'Configuration',
    icon: 'cog',
    body: BrainConfig as any,
    id: 'configuration',
  });
