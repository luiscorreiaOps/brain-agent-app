import fs from 'fs';
import process from 'process';
import os from 'os';
import path from 'path';
import { SOURCE_DIR } from './constants.ts';

export function isWSL() {
  if (process.platform !== 'linux') {
    return false;
  }

  if (os.release().toLowerCase().includes('microsoft')) {
    return true;
  }

  try {
    return fs.readFileSync('/proc/version', 'utf8').toLowerCase().includes('microsoft');
  } catch {
    return false;
  }
}

function loadJson(path: string) {
  const rawJson = fs.readFileSync(path, 'utf8');
  return JSON.parse(rawJson);
}

export function getPackageJson() {
  return loadJson(path.resolve(process.cwd(), 'package.json'));
}

export function getPluginJson() {
  return loadJson(path.resolve(process.cwd(), `${SOURCE_DIR}/plugin.json`));
}

export function getCPConfigVersion() {
  const cprcJson = path.resolve(process.cwd(), './.config', '.cprc.json');
  return fs.existsSync(cprcJson) ? loadJson(cprcJson).version : { version: 'unknown' };
}

export function hasReadme() {
  return fs.existsSync(path.resolve(process.cwd(), SOURCE_DIR, 'README.md'));
}

export async function getEntries() {
  return { module: path.resolve(process.cwd(), SOURCE_DIR, 'module.tsx') };
}
