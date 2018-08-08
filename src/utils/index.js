export * from './encoding';

export const unicodeToBuffer = str =>
  Buffer.from(str.split('').map(s => s.charCodeAt(0)));
