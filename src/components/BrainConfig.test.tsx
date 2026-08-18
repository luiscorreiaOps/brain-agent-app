const postMock = jest.fn().mockResolvedValue({});
const getMock = jest.fn().mockResolvedValue({ jsonData: {} });
const publishMock = jest.fn();

jest.mock('@grafana/runtime', () => ({
  getBackendSrv: () => ({
    post: postMock,
    get: getMock,
  }),
  getAppEvents: () => ({
    publish: publishMock,
  }),
  config: {
    bootData: {
      user: {
        orgRole: 'Admin',
      },
    },
  },
}));

import React from 'react';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { BrainConfig } from './BrainConfig';

const mockPlugin = {
  jsonData: {
    grafanaURL: 'http://localhost:3000',
  },
} as any;

// BrainConfig's mount-time useEffect re-fetches /api/plugins/brain-agent/
// settings and calls setState in a .then() that resolves on a later
// microtask than render() itself -- render() only wraps the synchronous
// part of mounting in act(), so without this, that state update lands
// outside any act() boundary and React logs the "not wrapped in act"
// warning (security-audit finding B2), regardless of what any later,
// separately-act()-wrapped code in the same test does.
async function renderAndFlushMountEffect(plugin: any) {
  const utils = render(<BrainConfig plugin={plugin} />);
  await act(async () => {
    await Promise.resolve();
  });
  return utils;
}

describe('BrainConfig', () => {
  beforeEach(() => {
    postMock.mockClear();
    getMock.mockClear();
    publishMock.mockClear();
  });

  it('does not reset the AES key when the confirm dialog is declined', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(false);
    await renderAndFlushMountEffect(mockPlugin);

    fireEvent.click(screen.getByText(/reset key/i));

    expect(confirmSpy).toHaveBeenCalled();
    expect(postMock).not.toHaveBeenCalledWith(expect.stringContaining('/crypto/reset'));
    confirmSpy.mockRestore();
  });

  it('resets the AES key only after the confirm dialog is accepted', async () => {
    const confirmSpy = jest.spyOn(window, 'confirm').mockReturnValue(true);
    await renderAndFlushMountEffect(mockPlugin);

    fireEvent.click(screen.getByText(/reset key/i));

    expect(confirmSpy).toHaveBeenCalled();
    expect(postMock).toHaveBeenCalledWith('/api/plugins/brain-agent/resources/crypto/reset');
    // The click handler's .then(() => notify(...)) resolves on a microtask
    // after this point -- wait for it before asserting, since it's a real
    // async continuation, not a synchronous side effect of the click.
    await waitFor(() => expect(publishMock).toHaveBeenCalledWith(
      expect.objectContaining({ payload: ['Key deleted and reset successfully.'] })
    ));
    confirmSpy.mockRestore();
  });

  it('saves the Grafana URL and RAG/retention settings for real on Save', async () => {
    await renderAndFlushMountEffect(mockPlugin);

    fireEvent.change(screen.getByLabelText(/grafana url/i), { target: { value: 'http://grafana.internal:3000' } });
    fireEvent.change(screen.getByLabelText(/data retention/i), { target: { value: '14' } });

    await act(async () => {
      fireEvent.click(screen.getByText(/save settings/i));
      // Flush the settings GET + POST promise chain inside handleSave.
      await Promise.resolve();
      await Promise.resolve();
    });

    expect(postMock).toHaveBeenCalledWith(
      '/api/plugins/brain-agent/settings',
      expect.objectContaining({
        jsonData: expect.objectContaining({
          grafanaURL: 'http://grafana.internal:3000',
          retentionDays: 14,
        }),
      })
    );
  });

  it('omits grafanaToken from the save payload when left blank, so an already-saved token is not wiped', async () => {
    await renderAndFlushMountEffect(mockPlugin);

    await act(async () => {
      fireEvent.click(screen.getByText(/save settings/i));
      await Promise.resolve();
      await Promise.resolve();
    });

    const [, body] = postMock.mock.calls[0];
    expect(body.secureJsonData).toBeUndefined();
  });
});
