export * from './encoding';

export const unicodeToUint8Array = str => {
  const res = new Uint8Array(str.length);
  let idx = 0;
  str.split('').forEach(s => {
    res[idx] = s.charCodeAt(0);
    idx += 1;
  });

  return res;
};

export const concatUint8Arrays = (a1, a2) => {
  const res = new Uint8Array(a1.length + a2.length);
  res.set(a1);
  res.set(a2, a1.length);
  return res;
};
